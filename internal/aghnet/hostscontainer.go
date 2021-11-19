package aghnet

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// DefaultHostsPaths returns the slice of paths default for the operating system
// to files and directories which are containing the hosts database.  The result
// is intended to be used within fs.FS so the initial slash is omitted.
func DefaultHostsPaths() (paths []string) {
	return defaultHostsPaths()
}

// hostsContainerPref is a prefix for logging and wrapping errors in
// HostsContainer's methods.
const hostsContainerPref = "hosts container"

// HostsContainer stores the relevant hosts database provided by the OS and
// processes both A/AAAA and PTR DNS requests for those.
type HostsContainer struct {
	// engLock protects rulesStrg and engine.
	engLock *sync.RWMutex

	// rulesStrg stores the rules obtained from the hosts' file.
	rulesStrg *filterlist.RuleStorage
	// engine serves rulesStrg.
	engine *urlfilter.DNSEngine

	// translator maps generated $dnsrewrite rules into hosts-syntax rules.
	translator map[string]string

	// done is the channel to sign closing the container.
	done chan struct{}

	// updates is the channel for receiving updated hosts.
	updates chan *netutil.IPMap
	// last is the set of hosts that was cached within last detected change.
	last *netutil.IPMap

	// fsys is the working file system to read hosts files from.
	fsys fs.FS

	// w tracks the changes in specified files and directories.
	w aghos.FSWatcher
	// patterns stores specified paths in the fs.Glob-compatible form.
	patterns []string
}

// ErrNoHostsPaths is returned when there are no valid paths to watch passed to
// the HostsContainer.
const ErrNoHostsPaths errors.Error = "no valid paths to hosts files provided"

// NewHostsContainer creates a container of hosts, that watches the paths with
// w.  paths shouldn't be empty and each of paths should locate either a file or
// a directory in fsys.  fsys and w must be non-nil.
func NewHostsContainer(
	fsys fs.FS,
	w aghos.FSWatcher,
	paths ...string,
) (hc *HostsContainer, err error) {
	defer func() { err = errors.Annotate(err, "%s: %w", hostsContainerPref) }()

	if len(paths) == 0 {
		return nil, ErrNoHostsPaths
	}

	var patterns []string
	patterns, err = pathsToPatterns(fsys, paths)
	if err != nil {
		return nil, err
	} else if len(patterns) == 0 {
		return nil, ErrNoHostsPaths
	}

	hc = &HostsContainer{
		engLock:  &sync.RWMutex{},
		done:     make(chan struct{}, 1),
		updates:  make(chan *netutil.IPMap, 1),
		last:     &netutil.IPMap{},
		fsys:     fsys,
		w:        w,
		patterns: patterns,
	}

	log.Debug("%s: starting", hostsContainerPref)

	// Load initially.
	if err = hc.refresh(); err != nil {
		return nil, err
	}

	for _, p := range paths {
		if err = w.Add(p); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("adding path: %w", err)
			}

			log.Debug("%s: file %q expected to exist but doesn't", hostsContainerPref, p)
		}
	}

	go hc.handleEvents()

	return hc, nil
}

// MatchRequest is the request processing method to resolve hostnames and
// addresses from the operating system's hosts files.
//
// res is nil for any request having not an A/AAAA or PTR type.  Results
// containing CNAME information may be queried again with the same question type
// and the returned CNAME for Host field of request.  Results are guaranteed to
// be direct, i.e. any returned CNAME resolves into actual address like an alias
// in hosts does, see man hosts (5).
//
// It's also safe for concurrent use.
func (hc *HostsContainer) MatchRequest(
	req urlfilter.DNSRequest,
) (res *urlfilter.DNSResult, ok bool) {
	switch req.DNSType {
	case dns.TypeA, dns.TypeAAAA, dns.TypePTR:
		log.Debug("%s: handling the request", hostsContainerPref)
	default:
		return nil, false
	}

	hc.engLock.RLock()
	defer hc.engLock.RUnlock()

	return hc.engine.MatchRequest(req)
}

// Translate returns the source hosts-syntax rule for the generated dnsrewrite
// rule or an empty string if the last doesn't exist.
func (hc *HostsContainer) Translate(rule string) (hostRule string) {
	hc.engLock.RLock()
	defer hc.engLock.RUnlock()

	return hc.translator[rule]
}

// Close implements the io.Closer interface for *HostsContainer.  Close must
// only be called once.  The returned err is always nil.
func (hc *HostsContainer) Close() (err error) {
	log.Debug("%s: closing", hostsContainerPref)

	close(hc.done)

	return nil
}

// Upd returns the channel into which the updates are sent.  The receivable
// map's values are guaranteed to be of type of *stringutil.Set.
func (hc *HostsContainer) Upd() (updates <-chan *netutil.IPMap) {
	return hc.updates
}

// pathsToPatterns converts paths into patterns compatible with fs.Glob.
func pathsToPatterns(fsys fs.FS, paths []string) (patterns []string, err error) {
	for i, p := range paths {
		var fi fs.FileInfo
		fi, err = fs.Stat(fsys, p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}

			// Don't put a filename here since it's already added by fs.Stat.
			return nil, fmt.Errorf("path at index %d: %w", i, err)
		}

		if fi.IsDir() {
			p = path.Join(p, "*")
		}

		patterns = append(patterns, p)
	}

	return patterns, nil
}

// handleEvents concurrently handles the events.  It closes the update channel
// of HostsContainer when finishes.  Used to be called within a goroutine.
func (hc *HostsContainer) handleEvents() {
	defer log.OnPanic(fmt.Sprintf("%s: handling events", hostsContainerPref))

	defer close(hc.updates)

	ok, eventsCh := true, hc.w.Events()
	for ok {
		select {
		case _, ok = <-eventsCh:
			if !ok {
				log.Debug("%s: watcher closed the events channel", hostsContainerPref)

				continue
			}

			if err := hc.refresh(); err != nil {
				log.Error("%s: %s", hostsContainerPref, err)
			}
		case _, ok = <-hc.done:
			// Go on.
		}
	}
}

// hostsParser is a helper type to parse rules from the operating system's hosts
// file.  It exists for only a single refreshing session.
type hostsParser struct {
	// rules builds the resulting rules list content.
	rules *strings.Builder

	// syntax maps generated $dnsrewrite rules into hosts-syntax rules.
	syntax map[string]string

	// cnameSet prevents duplicating cname rules.
	cnameSet *stringutil.Set

	// table stores only the unique IP-hostname pairs.  It's also sent to the
	// updates channel afterwards.
	table *netutil.IPMap
}

func (hc *HostsContainer) newHostsParser() (hp *hostsParser) {
	return &hostsParser{
		rules: &strings.Builder{},
		// For A/AAAA and PTRs.
		syntax:   make(map[string]string, hc.last.Len()*2),
		cnameSet: stringutil.NewSet(),
		table:    netutil.NewIPMap(hc.last.Len()),
	}
}

// parseFile is a aghos.FileWalker for parsing the files with hosts syntax.  It
// never signs to stop walking and never returns any additional patterns.
//
// See man hosts(5).
func (hp *hostsParser) parseFile(
	r io.Reader,
) (patterns []string, cont bool, err error) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		ip, hosts := hp.parseLine(s.Text())
		if ip == nil {
			continue
		}

		hp.addPairs(ip, hosts)
	}

	return nil, true, s.Err()
}

// parseLine parses the line having the hosts syntax ignoring invalid ones.
func (hp *hostsParser) parseLine(line string) (ip net.IP, hosts []string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, nil
	}

	if ip = net.ParseIP(fields[0]); ip == nil {
		return nil, nil
	}

loop:
	for _, f := range fields[1:] {
		switch hashIdx := strings.IndexByte(f, '#'); hashIdx {
		case 0:
			// The rest of the fields are a part of the comment so skip
			// immediately.
			break loop
		case -1:
			hosts = append(hosts, f)
		default:
			// Only a part of the field is a comment.
			hosts = append(hosts, f[:hashIdx])

			break loop
		}
	}

	return ip, hosts
}

// Simple types of hosts in hosts database.  Zero value isn't used to be able
// quizzaciously emulate nil with 0.
const (
	_ = iota
	hostAlias
	hostMain
)

// add tries to add the ip-host pair.  It returns:
//
//   hostAlias if the host is not the first one added for the ip.
//   hostMain  if the host is the first one added for the ip.
//   0         if the ip-host pair has already been added.
//
func (hp *hostsParser) add(ip net.IP, host string) (hostType int) {
	v, ok := hp.table.Get(ip)
	switch hosts, _ := v.(*stringutil.Set); {
	case ok && hosts.Has(host):
		return 0
	case hosts == nil:
		hosts = stringutil.NewSet(host)
		hp.table.Set(ip, hosts)

		return hostMain
	default:
		hosts.Add(host)

		return hostAlias
	}
}

// addPair puts the pair of ip and host to the rules builder if needed.  For
// each ip the first member of hosts will become the main one.
func (hp *hostsParser) addPairs(ip net.IP, hosts []string) {
	// Preproccesed format like:
	//
	//   ip host1 host2 ...
	//
	hostsLine := strings.Join(append([]string{ip.String()}, hosts...), " ")
	var mainHost string
	for _, host := range hosts {
		switch hp.add(ip, host) {
		case 0:
			continue
		case hostMain:
			mainHost = host
			added, addedPtr := hp.writeMainHostRule(host, ip)
			hp.syntax[added], hp.syntax[addedPtr] = hostsLine, hostsLine
		case hostAlias:
			pair := fmt.Sprint(host, " ", mainHost)
			if hp.cnameSet.Has(pair) {
				continue
			}
			// Since the hostAlias couldn't be returned from add before the
			// hostMain the mainHost shouldn't appear empty.
			hp.writeAliasHostRule(host, mainHost)
			hp.cnameSet.Add(pair)
		}

		log.Debug("%s: added ip-host pair %q-%q", hostsContainerPref, ip, host)
	}
}

// writeAliasHostRule writes the CNAME rule for the alias-host pair into
// internal builders.
func (hp *hostsParser) writeAliasHostRule(alias, host string) {
	const (
		nl = "\n"
		sc = ";"

		rwSuccess = rules.MaskSeparator + "$dnsrewrite=NOERROR" + sc + "CNAME" + sc
		constLen  = len(rules.MaskStartURL) + len(rwSuccess) + len(nl)
	)

	hp.rules.Grow(constLen + len(host) + len(alias))
	stringutil.WriteToBuilder(hp.rules, rules.MaskStartURL, alias, rwSuccess, host, nl)
}

// writeMainHostRule writes the actual rule for the qtype and the PTR for the
// host-ip pair into internal builders.
func (hp *hostsParser) writeMainHostRule(host string, ip net.IP) (added, addedPtr string) {
	arpa, err := netutil.IPToReversedAddr(ip)
	if err != nil {
		return
	}

	const (
		nl = "\n"
		sc = ";"
		sp = " "

		a    = "A"
		aaaa = "AAAA"
		ptr  = "PTR"

		rwSuccess    = "$dnsrewrite=NOERROR" + sc
		rwSuccessPTR = rwSuccess + ptr + sc

		constLen    = len(rules.MaskStartURL) + len(rules.MaskSeparator) + len(rwSuccess) + len(sc)
		constLenPtr = len(rules.MaskStartURL) + len(rules.MaskSeparator) + len(rwSuccessPTR)
	)

	var qtype string
	// The validation of the IP address has been performed earlier so it is
	// guaranteed to be either an IPv4 or an IPv6.
	if ip.To4() != nil {
		qtype = a
	} else {
		qtype = aaaa
	}

	ipStr := ip.String()
	fqdn := dns.Fqdn(host)

	rule := &strings.Builder{}
	rule.Grow(constLen + len(host) + len(qtype) + len(ipStr))
	stringutil.WriteToBuilder(
		rule,
		rules.MaskStartURL,
		host,
		rules.MaskSeparator,
		rwSuccess,
		qtype,
		sc,
		ipStr,
	)
	added = rule.String()

	rule.Reset()
	rule.Grow(constLenPtr + len(arpa) + len(fqdn))
	stringutil.WriteToBuilder(
		rule,
		rules.MaskStartURL,
		arpa,
		rules.MaskSeparator,
		rwSuccessPTR,
		fqdn,
	)
	addedPtr = rule.String()

	hp.rules.Grow(len(added) + len(addedPtr) + 2*len(nl))
	stringutil.WriteToBuilder(hp.rules, added, nl, addedPtr, nl)

	return added, addedPtr
}

// equalSet returns true if the internal hosts table just parsed equals target.
func (hp *hostsParser) equalSet(target *netutil.IPMap) (ok bool) {
	if hp.table.Len() != target.Len() {
		return false
	}

	hp.table.Range(func(ip net.IP, val interface{}) (cont bool) {
		v, hasIP := target.Get(ip)
		// ok is set to true if the target doesn't contain ip or if the
		// appropriate hosts set isn't equal to the checked one, i.e. the maps
		// have at least one disperancy.
		ok = !hasIP || !v.(*stringutil.Set).Equal(val.(*stringutil.Set))

		// Continue only if maps has no discrepancies.
		return !ok
	})

	// Return true if every value from the IP map has no disperancies with the
	// appropriate one from the target.
	return !ok
}

// sendUpd tries to send the parsed data to the ch.
func (hp *hostsParser) sendUpd(ch chan *netutil.IPMap) {
	log.Debug("%s: sending upd", hostsContainerPref)

	upd := hp.table
	select {
	case ch <- upd:
		// Updates are delivered.  Go on.
	case <-ch:
		ch <- upd
		log.Debug("%s: replaced the last update", hostsContainerPref)
	case ch <- upd:
		// The previous update was just read and the next one pushed.  Go on.
	default:
		log.Error("%s: the updates channel is broken", hostsContainerPref)
	}
}

// newStrg creates a new rules storage from parsed data.
func (hp *hostsParser) newStrg() (s *filterlist.RuleStorage, err error) {
	return filterlist.NewRuleStorage([]filterlist.RuleList{&filterlist.StringRuleList{
		ID:             -1,
		RulesText:      hp.rules.String(),
		IgnoreCosmetic: true,
	}})
}

// refresh gets the data from specified files and propagates the updates if
// needed.
//
// TODO(e.burkov):  Accept a parameter to specify the files to refresh.
func (hc *HostsContainer) refresh() (err error) {
	log.Debug("%s: refreshing", hostsContainerPref)

	hp := hc.newHostsParser()
	if _, err = aghos.FileWalker(hp.parseFile).Walk(hc.fsys, hc.patterns...); err != nil {
		return fmt.Errorf("refreshing : %w", err)
	}

	if hp.equalSet(hc.last) {
		log.Debug("%s: no updates detected", hostsContainerPref)

		return nil
	}
	defer hp.sendUpd(hc.updates)

	hc.last = hp.table.ShallowClone()

	var rulesStrg *filterlist.RuleStorage
	if rulesStrg, err = hp.newStrg(); err != nil {
		return fmt.Errorf("initializing rules storage: %w", err)
	}

	hc.resetEng(rulesStrg, hp.syntax)

	return nil
}

// resetEng updates container's engine and the translation map.
func (hc *HostsContainer) resetEng(rulesStrg *filterlist.RuleStorage, syntax map[string]string) {
	hc.engLock.Lock()
	defer hc.engLock.Unlock()

	hc.rulesStrg = rulesStrg
	hc.engine = urlfilter.NewDNSEngine(hc.rulesStrg)

	hc.translator = syntax
}

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/google/nftables"
)

var labelRE = regexp.MustCompile(`^[a-z0-9_*-]{1,63}$`)

type domain struct {
	set4, set6 *nftables.Set
	name       string
	wildcard   bool
	pattern    []string
}

type domainList struct {
	names map[string]*domain
	globs []*domain
}

func (l domainList) len() int {
    return len(l.names) + len(l.globs)
}

func parseName(name string) (glob, ok bool) {
	if len(name) > 253 {
		return false, false
	}
	for _, label := range strings.Split(name, ".") {
		if !labelRE.MatchString(label) {
			return false, false
		}
		if strings.Contains(label, "*") {
			if strings.Trim(label, "*") == "" {
				return false, false
			}
			glob = true
		}
	}
	return glob, true
}

func (d *daemon) loadDomains(path string) (domainList, error) {
	f, err := os.Open(path)
	if err != nil {
		return domainList{}, err
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Printf("error closing file: %v", err)
		}
	}(f)

	sets := map[string]*nftables.Set{}
	lookup := func(name string, want nftables.SetDatatype) (*nftables.Set, error) {
		if name == "" || name == "-" {
			return nil, nil
		}

		s := sets[name]
		if s == nil && d.cfg.dryRun {
			s = &nftables.Set{Name: name, Table: d.table, KeyType: want, HasTimeout: true}
		} else if s == nil {
			if s, err = d.nft.GetSetByName(d.table, name); err != nil {
				return nil, fmt.Errorf("set %s: %w", name, err)
			}
		}
		sets[name] = s

		if s.KeyType.Name != want.Name {
			return nil, fmt.Errorf("set %s holds %s, need %s", name, s.KeyType.Name, want.Name)
		}

		if !s.HasTimeout {
			return nil, fmt.Errorf("set %s needs 'flags timeout'", name)
		}

		return s, nil
	}

	list := domainList{names: map[string]*domain{}}
	globs := map[string]*domain{}
	sc := bufio.NewScanner(f)

	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if len(fields) > 3 {
			return domainList{}, fmt.Errorf("%s:%d: too many fields", path, n)
		}

		entry := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		name, wildcard := strings.CutPrefix(entry, "*.")
		glob, ok := parseName(name)
		if !ok {
			return domainList{}, fmt.Errorf("%s:%d: invalid domain %q", path, n, entry)
		}

		setNames := [2]string{d.cfg.def4, d.cfg.def6}
		copy(setNames[:], fields[1:])
		dom := &domain{name: name, wildcard: wildcard}
		if glob {
			dom.pattern = strings.Split(name, ".")
		}
		if dom.set4, err = lookup(setNames[0], nftables.TypeIPAddr); err == nil {
			dom.set6, err = lookup(setNames[1], nftables.TypeIP6Addr)
		}

		if err == nil && dom.set4 == nil && dom.set6 == nil {
			err = errors.New("no set given (use -4/-6 or list sets)")
		}

		if err != nil {
			return domainList{}, fmt.Errorf("%s:%d: %w", path, n, err)
		}

		seen := list.names
		if glob {
			seen = globs
		}
		if old := seen[name]; old != nil {
			old.wildcard = old.wildcard || wildcard
			continue
		}
		seen[name] = dom
		if glob {
			list.globs = append(list.globs, dom)
		}
	}
	if err := sc.Err(); err != nil {
		return domainList{}, err
	}
	return list, nil
}

func under(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func (d *daemon) match(name string) (*domain, string) {
	for zone, exact := name, true; ; exact = false {
		if dom := d.domains.names[zone]; dom != nil && (exact || dom.wildcard) {
			return dom, zone
		}
		if dom := d.domains.matchGlob(zone, exact); dom != nil {
			return dom, zone
		}

		_, parent, ok := strings.Cut(zone, ".")
		if !ok {
			return nil, ""
		}
		zone = parent
	}
}

func (l domainList) matchGlob(name string, exact bool) *domain {
	if len(l.globs) == 0 {
		return nil
	}
	labels := strings.Split(name, ".")
	for _, dom := range l.globs {
		if (exact || dom.wildcard) && matchLabels(dom.pattern, labels) {
			return dom
		}
	}
	return nil
}

func matchLabels(pattern, labels []string) bool {
	if len(pattern) != len(labels) {
		return false
	}
	for i, p := range pattern {
		if !matchLabel(p, labels[i]) {
			return false
		}
	}
	return true
}

func matchLabel(pat, s string) bool {
	parts := strings.Split(pat, "*")
	if len(parts) == 1 {
		return pat == s
	}
	first, last := parts[0], parts[len(parts)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	s = s[len(first) : len(s)-len(last)]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return true
}

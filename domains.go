package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/nftables"
)

var domainRE = regexp.MustCompile(`^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$`)

type domain struct {
	set4, set6 *nftables.Set
	wildcard   bool
}

func (d *daemon) loadDomains(path string) (map[string]*domain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

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

	domains := map[string]*domain{}
	sc := bufio.NewScanner(f)

	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if len(fields) > 3 {
			return nil, fmt.Errorf("%s:%d: too many fields", path, n)
		}

		entry := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		name, wildcard := strings.CutPrefix(entry, "*.")
		if len(name) > 253 || !domainRE.MatchString(name) {
			return nil, fmt.Errorf("%s:%d: invalid domain %q", path, n, entry)
		}

		setNames := [2]string{d.cfg.def4, d.cfg.def6}
		copy(setNames[:], fields[1:])
		dom := &domain{wildcard: wildcard}
		if dom.set4, err = lookup(setNames[0], nftables.TypeIPAddr); err == nil {
			dom.set6, err = lookup(setNames[1], nftables.TypeIP6Addr)
		}

		if err == nil && dom.set4 == nil && dom.set6 == nil {
			err = errors.New("no set given (use -4/-6 or list sets)")
		}

		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}

		if old := domains[name]; old != nil {
			old.wildcard = old.wildcard || wildcard
			continue
		}
		domains[name] = dom
	}
	return domains, sc.Err()
}

func (d *daemon) match(name string) *domain {
	if dom := d.domains[name]; dom != nil {
		return dom
	}

	for {
		_, parent, ok := strings.Cut(name, ".")
		if !ok {
			return nil
		}
		name = parent

		if dom := d.domains[name]; dom != nil && dom.wildcard {
			return dom
		}
	}
}

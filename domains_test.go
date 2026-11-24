package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"
)

func loadList(t testing.TB, conf string, opts ...func(*config)) (*testEnv, error) {
	t.Helper()
	env := newTestDaemon(t, append([]func(*config){func(cfg *config) {
		cfg.def4, cfg.def6 = "v4", "v6"
	}}, opts...)...)
	path := filepath.Join(t.TempDir(), "domains.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	env.cfg.domFile = path
	domains, err := env.loadDomains(path)
	env.domains = domains
	return env, err
}

func TestMatch(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, `
example.com                 # this name only
*.wild.example.com          # the name and everything under it
*.Mixed.Example.ORG.
deep.sub.example.net
*.example.net
`)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", false},
		{"wild.example.com", true},
		{"a.wild.example.com", true},
		{"a.b.c.wild.example.com", true},
		{"notwild.example.com", false},
		{"mixed.example.org", true},
		{"x.mixed.example.org", true},
		{"deep.sub.example.net", true},
		{"other.sub.example.net", true},
		{"example.net", true},
		{"example.net.evil.com", false},
		{"com", false},
		{"", false},
	} {
		if dom, _ := env.match(c.name); (dom != nil) != c.want {
			t.Errorf("match(%q) = %v, want %v", c.name, dom != nil, c.want)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, `
ex*.example.com             # one label starting with "ex", under example.com
*.api*.example.org          # the matching name and everything under it
*-prod.Example.NET.
a*b*c.example.io
`)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, zone string
	}{
		{"ex.example.com", "ex.example.com"},
		{"ex1.example.com", "ex1.example.com"},
		{"example.example.com", "example.example.com"},
		{"ex-staging.example.com", "ex-staging.example.com"},
		{"a.ex1.example.com", ""},
		{"x.example.com", ""},
		{"e.example.com", ""},
		{"example.com", ""},
		{"ex1.example.com.evil.net", ""},
		{"ex1.notexample.com", ""},
		{"ex1.sub.example.com", ""},
		{"api.example.org", "api.example.org"},
		{"api2.example.org", "api2.example.org"},
		{"v1.api2.example.org", "api2.example.org"},
		{"a.b.api-eu.example.org", "api-eu.example.org"},
		{"myapi.example.org", ""},
		{"example.org", ""},
		{"db-prod.example.net", "db-prod.example.net"},
		{"-prod.example.net", "-prod.example.net"},
		{"db-prod2.example.net", ""},
		{"abc.example.io", "abc.example.io"},
		{"a-b-c.example.io", "a-b-c.example.io"},
		{"axxbyyc.example.io", "axxbyyc.example.io"},
		{"acb.example.io", ""},
		{"ab.example.io", ""},
		{"", ""},
	} {
		dom, zone := env.match(c.name)
		if (dom != nil) != (c.zone != "") || zone != c.zone {
			t.Errorf("match(%q) = %v, zone %q; want zone %q", c.name, dom != nil, zone, c.zone)
		}
	}
}

func TestPlainNamesWinOverPatterns(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, "ex*.example.com v4 -\nex1.example.com - v6\n*.example.com v4 v6\n")
	if err != nil {
		t.Fatal(err)
	}
	if dom, _ := env.match("ex1.example.com"); dom == nil || dom.set4 != nil {
		t.Errorf("ex1.example.com matched %+v, want the plain entry", dom)
	}
	if dom, _ := env.match("ex2.example.com"); dom == nil || dom.set6 != nil {
		t.Errorf("ex2.example.com matched %+v, want the pattern", dom)
	}
	if dom, zone := env.match("a.ex2.example.com"); dom == nil || zone != "example.com" {
		t.Errorf("a.ex2.example.com matched %+v at %q, want the wildcard entry", dom, zone)
	}
}

func TestListingAPatternTwice(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, "ex*.example.com v4 -\n*.ex*.example.com v4 v6\n")
	if err != nil {
		t.Fatal(err)
	}
	if n := env.domains.len(); n != 1 {
		t.Errorf("loaded %d entries, want 1", n)
	}
	dom, _ := env.match("ex1.example.com")
	if dom == nil || dom.set6 != nil {
		t.Fatalf("ex1.example.com: got %+v, want the sets of the first entry", dom)
	}
	if sub, _ := env.match("a.ex1.example.com"); sub != dom {
		t.Error("a.ex1.example.com should match through the wildcard entry")
	}
}

func TestMatchLabel(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"ex*", "ex", true},
		{"ex*", "example", true},
		{"ex*", "e", false},
		{"ex*", "xex", false},
		{"*ex", "ex", true},
		{"*ex", "complex", true},
		{"*ex", "exa", false},
		{"e*x", "ex", true},
		{"e*x", "e-x", true},
		{"e*x", "x", false},
		{"a*a", "a", false},
		{"a*a", "aa", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "abbc", true},
		{"a*b*c", "acbc", true},
		{"a*b*c", "acb", false},
		{"a**b", "ab", true},
		{"plain", "plain", true},
		{"plain", "plainer", false},
	} {
		if got := matchLabel(c.pat, c.s); got != c.want {
			t.Errorf("matchLabel(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestListingANameTwice(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, "example.com v4 -\n*.example.com v4 v6\n")
	if err != nil {
		t.Fatal(err)
	}
	dom, _ := env.match("example.com")
	if dom == nil || dom.set4 == nil || dom.set4.Name != "v4" || dom.set6 != nil {
		t.Fatalf("example.com: got %+v, want the sets of the first entry", dom)
	}
	if sub, _ := env.match("sub.example.com"); sub != dom {
		t.Error("sub.example.com should match through the wildcard entry")
	}
}

func TestListSyntax(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		conf string
		err  string
	}{
		{"a wildcard", "*.example.com\n", ""},
		{"comments and blank lines", "\n# nothing here\n   \nexample.com # trailing\n", ""},
		{"an explicit pair of sets", "example.com v4 v6\n", ""},
		{"one family left out", "example.com v4 -\n", ""},
		{"a lone star", "*\n", "invalid domain"},
		{"a star without a name", "*.\n", "invalid domain"},
		{"a star in the middle", "a.*.example.com\n", "invalid domain"},
		{"a star at the front of a label", "*example.com\n", ""},
		{"a star inside a label", "ex*ample.com\n", ""},
		{"a star at the end of a label", "ex*.example.com\n", ""},
		{"a star inside a label under a wildcard", "*.ex*.example.com\n", ""},
		{"a star inside a deeper label", "www.ex*.example.com\n", ""},
		{"stars inside the same label", "a*b*c.example.com\n", ""},
		{"a label of stars only", "**.example.com\n", "invalid domain"},
		{"a lone star in the middle of a pattern", "ex*.*.example.com\n", "invalid domain"},
		{"a pattern that is too long", strings.Repeat("a*.", 85) + "com\n", "invalid domain"},
		{"a label that is too long", strings.Repeat("a", 63) + "*.example.com\n", "invalid domain"},
		{"an underscore is allowed", "_dmarc.example.com\n", ""},
		{"too many fields", "example.com v4 v6 extra\n", "too many fields"},
		{"no set at all", "example.com - -\n", "no set given"},
		{"an unknown set", "example.com nosuch -\n", "no such set"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadList(t, c.conf)
			switch {
			case c.err == "" && err != nil:
				t.Errorf("%q was rejected: %v", c.conf, err)
			case c.err != "" && err == nil:
				t.Errorf("%q was accepted, want an error about %q", c.conf, c.err)
			case c.err != "" && err != nil && !strings.Contains(err.Error(), c.err):
				t.Errorf("error = %v, want it to mention %q", err, c.err)
			}
		})
	}
}

func TestSetsAreChecked(t *testing.T) {
	t.Parallel()
	t.Run("the key type has to match the family", func(t *testing.T) {
		t.Parallel()
		_, err := loadList(t, "example.com v6 -\n")
		if err == nil || !strings.Contains(err.Error(), "holds") {
			t.Errorf("error = %v, want it to reject the key type", err)
		}
	})

	t.Run("the set needs a timeout flag", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.conn.sets["notimeout"] = &nftables.Set{Name: "notimeout", KeyType: nftables.TypeIPAddr}
		path := filepath.Join(t.TempDir(), "d.conf")
		if err := os.WriteFile(path, []byte("example.com notimeout -\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := env.loadDomains(path); err == nil || !strings.Contains(err.Error(), "flags timeout") {
			t.Errorf("error = %v, want it to ask for a timeout flag", err)
		}
	})

	t.Run("a dry run does not ask the kernel", func(t *testing.T) {
		t.Parallel()
		env, err := loadList(t, "example.com anything -\n", func(cfg *config) { cfg.dryRun = true })
		if err != nil {
			t.Fatal(err)
		}
		if len(env.conn.calls) != 0 {
			t.Errorf("a dry run used the connection: %v", env.conn.ops())
		}
	})
}

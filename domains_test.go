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
		if got := env.match(c.name) != nil; got != c.want {
			t.Errorf("match(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestListingANameTwice(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, "example.com v4 -\n*.example.com v4 v6\n")
	if err != nil {
		t.Fatal(err)
	}
	dom := env.match("example.com")
	if dom == nil || dom.set4 == nil || dom.set4.Name != "v4" || dom.set6 != nil {
		t.Fatalf("example.com: got %+v, want the sets of the first entry", dom)
	}
	if env.match("sub.example.com") != dom {
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
		{"two stars", "**.example.com\n", "invalid domain"},
		{"a star without a dot", "*example.com\n", "invalid domain"},
		{"a star inside a label", "ex*ample.com\n", "invalid domain"},
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

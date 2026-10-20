// Package config loads the CA hierarchy definition from config/hierarchy.yaml.
//
// To keep the whole environment buildable fully offline (no external Go modules),
// this package implements a small YAML reader scoped to the known schema of
// hierarchy.yaml rather than depending on gopkg.in/yaml.v3.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// KeySpec describes a key algorithm choice for a CA tier.
type KeySpec struct {
	Type  string // "rsa" | "ecdsa"
	Bits  int    // for rsa
	Curve string // for ecdsa: "P-256" | "P-384" | "P-521"
}

// CA describes one certificate authority in the hierarchy.
type CA struct {
	Name         string
	Parent       string // name of the signing CA ("" => self-signed root)
	Key          KeySpec
	ValidityDays int
	PathLen      int
	HasPathLen   bool
	Slot         string // simulated-HSM slot label
	AIA          string // OCSP URL embedded in issued certs
	CDP          string // CRL URL embedded in issued certs
}

// Profile models an AD certificate template (template -> GPO mapping).
type Profile struct {
	Name         string
	EKU          []string
	KeyUsage     []string
	ValidityDays int
}

// Crypto holds crypto-agility settings.
type Crypto struct {
	DefaultHash string
	PQCReady    bool
}

// Config is the fully parsed hierarchy definition.
type Config struct {
	Organization  string
	Root          CA
	Intermediates []CA
	Issuing       []CA
	Profiles      map[string]Profile
	Crypto        Crypto
}

// Load reads and parses hierarchy.yaml from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	doc := parseYAML(string(data))
	c := &Config{
		Organization: doc.scalar("organization"),
		Profiles:     map[string]Profile{},
	}

	// root
	if r := doc.child("root"); r != nil {
		c.Root = caFromNode(r)
	} else {
		return nil, fmt.Errorf("config: missing 'root'")
	}

	// intermediates (list)
	for _, n := range doc.list("intermediates") {
		c.Intermediates = append(c.Intermediates, caFromNode(n))
	}

	// issuing (list)
	for _, n := range doc.list("issuing") {
		c.Issuing = append(c.Issuing, caFromNode(n))
	}

	// profiles (map of maps)
	if p := doc.child("profiles"); p != nil {
		for _, key := range p.order {
			pn := p.children[key]
			c.Profiles[key] = Profile{
				Name:         key,
				EKU:          pn.strList("eku"),
				KeyUsage:     pn.strList("key_usage"),
				ValidityDays: pn.intVal("validity_days"),
			}
		}
	}

	// crypto
	if cr := doc.child("crypto"); cr != nil {
		c.Crypto = Crypto{
			DefaultHash: cr.scalar("default_hash"),
			PQCReady:    cr.boolVal("pqc_ready"),
		}
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func caFromNode(n *node) CA {
	ca := CA{
		Name:         n.scalar("name"),
		Parent:       n.scalar("parent"),
		ValidityDays: n.intVal("validity_days"),
		Slot:         n.scalar("slot"),
		AIA:          n.scalar("aia"),
		CDP:          n.scalar("cdp"),
	}
	if k := n.child("key"); k != nil {
		ca.Key = KeySpec{
			Type:  k.scalar("type"),
			Bits:  k.intVal("bits"),
			Curve: k.scalar("curve"),
		}
	}
	if v, ok := n.scalarOK("path_len"); ok {
		if iv, err := strconv.Atoi(v); err == nil {
			ca.PathLen = iv
			ca.HasPathLen = true
		}
	}
	return ca
}

func (c *Config) validate() error {
	if c.Root.Name == "" {
		return fmt.Errorf("config: root.name required")
	}
	if len(c.Intermediates) == 0 {
		return fmt.Errorf("config: at least one intermediate required")
	}
	if len(c.Issuing) == 0 {
		return fmt.Errorf("config: at least one issuing CA required")
	}
	for _, ca := range append(append([]CA{c.Root}, c.Intermediates...), c.Issuing...) {
		if err := validateKey(ca.Name, ca.Key); err != nil {
			return err
		}
	}
	return nil
}

func validateKey(name string, k KeySpec) error {
	switch k.Type {
	case "rsa":
		if k.Bits < 2048 {
			return fmt.Errorf("config: %s rsa bits must be >= 2048 (got %d)", name, k.Bits)
		}
	case "ecdsa":
		switch k.Curve {
		case "P-256", "P-384", "P-521":
		default:
			return fmt.Errorf("config: %s unsupported ecdsa curve %q", name, k.Curve)
		}
	default:
		return fmt.Errorf("config: %s unsupported key type %q", name, k.Type)
	}
	return nil
}

// AllCAs returns root, intermediates, and issuing CAs in dependency order.
func (c *Config) AllCAs() []CA {
	out := []CA{c.Root}
	out = append(out, c.Intermediates...)
	out = append(out, c.Issuing...)
	return out
}

// --- tiny YAML reader (indentation-based, scoped to our schema) ---

type node struct {
	value    string           // scalar value if leaf
	children map[string]*node // mapping entries
	order    []string         // key order
	items    []*node          // sequence items
}

func newNode() *node { return &node{children: map[string]*node{}} }

func (n *node) child(key string) *node {
	if n == nil {
		return nil
	}
	return n.children[key]
}

func (n *node) scalar(key string) string {
	c := n.child(key)
	if c == nil {
		return ""
	}
	return c.value
}

func (n *node) scalarOK(key string) (string, bool) {
	c := n.child(key)
	if c == nil {
		return "", false
	}
	return c.value, true
}

func (n *node) intVal(key string) int {
	v, err := strconv.Atoi(strings.TrimSpace(n.scalar(key)))
	if err != nil {
		return 0
	}
	return v
}

func (n *node) boolVal(key string) bool {
	return strings.EqualFold(strings.TrimSpace(n.scalar(key)), "true")
}

func (n *node) list(key string) []*node {
	c := n.child(key)
	if c == nil {
		return nil
	}
	return c.items
}

// strList parses an inline flow list `[a, b, c]` or a single scalar.
func (n *node) strList(key string) []string {
	v := n.scalar(key)
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	parts := strings.Split(v, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseYAML parses the subset of YAML used by hierarchy.yaml:
// mappings, sequences of mappings, scalars, inline flow lists, and inline maps.
func parseYAML(text string) *node {
	type frame struct {
		indent int
		n      *node
	}
	root := newNode()
	stack := []frame{{indent: -1, n: root}}

	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := countIndent(line)
		content := strings.TrimSpace(line)

		// pop to parent at a smaller indent
		for len(stack) > 1 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1].n

		if strings.HasPrefix(content, "- ") || content == "-" {
			// sequence item
			item := newNode()
			parent.items = append(parent.items, item)
			rest := strings.TrimSpace(strings.TrimPrefix(content, "-"))
			if rest != "" {
				// inline "key: value" starting the item
				applyKV(item, rest)
				// push item so subsequent deeper keys attach to it
				stack = append(stack, frame{indent: indent, n: item})
				// also push a pseudo for the inline key if it opened a map? not needed
			} else {
				stack = append(stack, frame{indent: indent, n: item})
			}
			continue
		}

		// mapping "key: value" or "key:"
		key, val, _ := strings.Cut(content, ":")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		child := newNode()
		if _, exists := parent.children[key]; !exists {
			parent.order = append(parent.order, key)
		}
		parent.children[key] = child
		if val != "" && !strings.HasPrefix(val, "{") {
			child.value = stripQuotes(val)
		} else if strings.HasPrefix(val, "{") {
			applyInlineMap(child, val)
		}
		stack = append(stack, frame{indent: indent, n: child})
	}
	return root
}

// applyKV handles "key: value" inside a sequence item header line.
func applyKV(item *node, kv string) {
	key, val, found := strings.Cut(kv, ":")
	if !found {
		return
	}
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	child := newNode()
	item.children[key] = child
	item.order = append(item.order, key)
	if strings.HasPrefix(val, "{") {
		applyInlineMap(child, val)
	} else if val != "" {
		child.value = stripQuotes(val)
	}
}

// applyInlineMap parses `{ a: 1, b: two }`.
func applyInlineMap(n *node, s string) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = stripQuotes(strings.TrimSpace(v))
		c := newNode()
		c.value = v
		n.children[k] = c
		n.order = append(n.order, k)
	}
}

func stripComment(line string) string {
	// remove trailing "# comment" not inside quotes (schema has no '#' in values)
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
		} else if c == '#' {
			return line[:i]
		}
	}
	return line
}

func countIndent(line string) int {
	n := 0
	for _, c := range line {
		if c == ' ' {
			n++
		} else {
			break
		}
	}
	return n
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

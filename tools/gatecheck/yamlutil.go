package main

import (
	"encoding/json"
	"strconv"

	"gopkg.in/yaml.v3"
)

// parseYAML returns the root node of a document, or nil for an empty one.
func parseYAML(text string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil
	}
	return doc.Content[0], nil
}

// path walks mapping keys and returns the value and key node of the last one.
func path(n *yaml.Node, keys ...string) (val, key *yaml.Node) {
	val = n
	for _, k := range keys {
		val, key = mapGet(val, k)
		if val == nil {
			return nil, nil
		}
	}
	return val, key
}

// item is one element of a sequence with a canonical form that ignores key
// order and formatting, and the line it starts on.
type item struct {
	canon string
	line  int
}

func items(n *yaml.Node) []item {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]item, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, item{canon(c), c.Line})
	}
	return out
}

// canon is the node's value as sorted-key JSON, or the bare scalar.
func canon(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return strconv.Itoa(n.Line)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func set(in []item) map[string]bool {
	m := map[string]bool{}
	for _, i := range in {
		m[i.canon] = true
	}
	return m
}

// newItems returns the items of head that base does not have.
func newItems(base, head []item) []item {
	have := set(base)
	var out []item
	for _, i := range head {
		if !have[i.canon] {
			out = append(out, i)
		}
	}
	return out
}

// goneItems returns the items of base that head no longer has.
func goneItems(base, head []item) []item { return newItems(head, base) }

// lineOr returns the node's line, or def for a missing node.
func lineOr(n *yaml.Node, def int) int {
	if n == nil {
		return def
	}
	return n.Line
}

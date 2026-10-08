package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// identityQuery runs a GraphQL query against Identity Protection. The route
// takes mutations too and its scope is a write scope, so anything but a
// query is refused here.
func identityQuery(ctx context.Context, d Deps, in Input) (map[string]any, error) {
	if strings.TrimSpace(in.Query) == "" {
		return nil, errors.New("this action needs query, a GraphQL query document")
	}
	if op := graphqlWrite(in.Query); op != "" {
		return nil, fmt.Errorf("GraphQL %s documents are refused: this tool only reads", op)
	}
	body := map[string]any{"query": in.Query}
	if len(in.Variables) > 0 {
		body["variables"] = in.Variables
	}
	raw, err := d.Client.Do(ctx, "post_graphql", falcon.Params{Body: body})
	if err != nil {
		return nil, err
	}
	var r struct {
		Data   any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decoding GraphQL response: %w", err)
	}
	out := capObject(times(r.Data))
	if len(r.Errors) > 0 {
		msgs := make([]string, len(r.Errors))
		for i, e := range r.Errors {
			msgs[i] = e.Message
		}
		out["errors"] = msgs
	}
	return out, nil
}

// graphqlWrite returns "mutation" or "subscription" if the document defines
// such an operation, else "". It reads keywords only outside every brace,
// bracket and parenthesis, skipping strings and comments; a document it
// cannot read cleanly counts as a write.
func graphqlWrite(doc string) string {
	depth := 0
	for i := 0; i < len(doc); i++ {
		switch c := doc[i]; {
		case c == '#':
			for i < len(doc) && doc[i] != '\n' {
				i++
			}
		case strings.HasPrefix(doc[i:], `"""`):
			end := -1
			for j := i + 3; j+3 <= len(doc); j++ {
				if doc[j] == '\\' && strings.HasPrefix(doc[j+1:], `"""`) {
					j += 3
					continue
				}
				if strings.HasPrefix(doc[j:], `"""`) {
					end = j
					break
				}
			}
			if end < 0 {
				return "mutation"
			}
			i = end + 2
		case c == '"':
			i++
			for i < len(doc) && doc[i] != '"' {
				if doc[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(doc) {
				return "mutation"
			}
		case c == '{' || c == '(' || c == '[':
			depth++
		case c == '}' || c == ')' || c == ']':
			if depth--; depth < 0 {
				return "mutation"
			}
		case depth == 0 && nameStart(c):
			j := i
			for j < len(doc) && (nameStart(doc[j]) || doc[j] >= '0' && doc[j] <= '9') {
				j++
			}
			if w := doc[i:j]; w == "mutation" || w == "subscription" {
				return w
			}
			i = j - 1
		}
	}
	return ""
}

func nameStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

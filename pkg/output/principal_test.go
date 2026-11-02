package output

import (
	"encoding/json"
	"sort"
	"testing"
)

// TestPrincipalUnmarshalJSON verifies every principal encoding accepted by
// AWS policy documents parses into a usable form
func TestPrincipalUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wildcard bool
		wantList []string
	}{
		{"wildcard string", `"*"`, true, []string{"*"}},
		{"object wildcard", `{"AWS": "*"}`, true, []string{"*"}},
		{"array wildcard", `{"AWS": ["*"]}`, true, []string{"*"}},
		{"bare arn string", `"arn:aws:iam::123456789012:root"`, false, []string{"arn:aws:iam::123456789012:root"}},
		{"object single", `{"AWS": "arn:aws:iam::123456789012:user/admin"}`, false, []string{"arn:aws:iam::123456789012:user/admin"}},
		{"object array", `{"AWS": ["arn:1", "arn:2"]}`, false, []string{"arn:1", "arn:2"}},
		{"array of objects", `[{"AWS": "arn:1"}, {"Service": "svc"}]`, false, []string{"arn:1", "svc"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Principal
			if err := json.Unmarshal([]byte(tt.json), &p); err != nil {
				t.Fatalf("failed to unmarshal %s: %v", tt.json, err)
			}
			if p.IsWildcard() != tt.wildcard {
				t.Errorf("Expected IsWildcard %v, got %v", tt.wildcard, p.IsWildcard())
			}
			got := p.List()
			sort.Strings(got)
			want := append([]string(nil), tt.wantList...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("Expected list %v, got %v", want, got)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("Expected list %v, got %v", want, got)
					break
				}
			}
		})
	}
}

// TestPrincipalUnmarshalJSON_Structured verifies nested structured
// principals parse without error and are not treated as wildcards
func TestPrincipalUnmarshalJSON_Structured(t *testing.T) {
	for _, doc := range []string{
		`{"AWS": {"CanonicalUser": {"ID": "123", "DisplayName": "admin"}}}`,
		`{"AWS": {"CanonicalUser": "16d2a3a8a8b5dbe0e2c4a1d6f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a"}}`,
	} {
		var p Principal
		if err := json.Unmarshal([]byte(doc), &p); err != nil {
			t.Errorf("structured principal must parse (%s): %v", doc, err)
		}
		if p.IsWildcard() {
			t.Errorf("structured principal must not be a wildcard (%s)", doc)
		}
	}
}

// TestPrincipalUnmarshalJSON_Errors verifies unparseable principals are
// rejected instead of silently producing an empty (safe-looking) value
func TestPrincipalUnmarshalJSON_Errors(t *testing.T) {
	for _, doc := range []string{`{}`, `42`, `{"AWS": 42}`} {
		var p Principal
		if err := json.Unmarshal([]byte(doc), &p); err == nil {
			t.Errorf("Expected error for %s, got value %+v", doc, p)
		}
	}
}

// TestPrincipalMarshalJSON verifies the original document form survives
// serialization so reports keep the provider's encoding
func TestPrincipalMarshalJSON(t *testing.T) {
	original := `{"AWS":["arn:1","arn:2"]}`
	var p Principal
	if err := json.Unmarshal([]byte(original), &p); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(out) != original {
		t.Errorf("Expected %s, got %s", original, string(out))
	}
}

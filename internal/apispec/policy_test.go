package apispec

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

const exampleDocument = `{
  "openapi":"3.0.3",
  "info":{"title":"Inventory","version":"1"},
  "paths":{
    "/api/items/{id}":{
      "get":{
        "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],
        "responses":{"200":{"description":"OK"}}
      }
    },
    "/api/items":{
      "post":{
        "requestBody":{"required":true,"content":{"application/json":{"schema":{
          "type":"object","required":["name"],"properties":{"name":{"type":"string"}}
        }}}},
        "responses":{"201":{"description":"Created"}}
      }
    }
  }
}`

func TestOpenAPIRequestContract(t *testing.T) {
	policy, err := Compile(context.Background(), "block", "/api", exampleDocument)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Endpoints) != 2 {
		t.Fatalf("expected two registered operations, got %v", policy.Endpoints)
	}
	for _, tc := range []struct {
		method, path, body string
		valid              bool
	}{
		{"GET", "/api/items/12", "", true},
		{"GET", "/api/items/item-name", "", false},
		{"GET", "/api/unknown", "", false},
		{"GET", "/apiary", "", true},
		{"POST", "/api/items", `{"name":"Sample"}`, true},
		{"POST", "/api/items", `{"name":12}`, false},
		{"POST", "/api/items", `{}`, false},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if result := policy.Check(req, []byte(tc.body)); (result == "") != tc.valid {
			t.Errorf("%s %s: result %q, expected valid=%v", tc.method, tc.path, result, tc.valid)
		}
	}
}

func TestOpenAPIDoesNotLoadRemoteReferences(t *testing.T) {
	doc := strings.Replace(exampleDocument, `"type":"integer"`, `"$ref":"https://example.invalid/schemas/id.json"`, 1)
	if _, err := Compile(context.Background(), "observe", "/api", doc); err == nil {
		t.Fatal("expected external reference to be rejected")
	}
}

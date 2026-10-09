package cisaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func list(items string, token string) []byte {
	return []byte(fmt.Sprintf(`{"metadata":{"continue":%q},"items":%s}`, token, items))
}

func TestRolesPaginationAndOutput(t *testing.T) {
	var calls []string
	fetch := func(path string) ([]byte, error) {
		calls = append(calls, path)
		switch path {
		case "/apis/rbac.authorization.k8s.io/v1/roles?limit=500":
			return list(`[{"metadata":{"name":"wild","namespace":"ns"},"rules":[{"verbs":["*"]}]}]`, "a+b/="), nil
		case "/apis/rbac.authorization.k8s.io/v1/roles?continue=a%2Bb%2F%3D&limit=500":
			return list(`[{"metadata":{"name":"mixed","namespace":"ns"},"rules":[{"verbs":["*","get"]}]},{"metadata":{"name":"empty","namespace":"ns"}}]`, ""), nil
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=500":
			return list(`[{"metadata":{"name":"read"},"rules":[{"verbs":["get"]}]}]`, ""), nil
		}
		return nil, fmt.Errorf("unexpected query %s", path)
	}
	var out bytes.Buffer
	if err := Run("roles", fetch, &out); err != nil {
		t.Fatal(err)
	}
	want := "**role_name: wild role_namespace: ns role_rules: [{\"verbs\":[\"*\"]}] role_is_compliant: false\n" +
		"**role_name: mixed role_namespace: ns role_rules: [{\"verbs\":[\"*\",\"get\"]}] role_is_compliant: true\n" +
		"**role_name: empty role_namespace: ns role_rules: null role_is_compliant: true\n" +
		"**clusterrole_name: read clusterrole_rules: [{\"verbs\":[\"get\"]}] clusterrole_is_compliant: true\n"
	if out.String() != want {
		t.Fatalf("got %s; want %s", out.String(), want)
	}
	if len(calls) != 3 {
		t.Fatal(calls)
	}
}

func TestServiceAccountTruthTable(t *testing.T) {
	var accounts, pods []map[string]any
	states := []any{nil, false, true}
	for i, sa := range states {
		accounts = append(accounts, map[string]any{"metadata": map[string]string{"namespace": "ns", "name": fmt.Sprint("sa", i)}, "automountServiceAccountToken": sa})
		for j, pod := range states {
			pods = append(pods, map[string]any{"metadata": map[string]string{"namespace": "ns", "name": fmt.Sprintf("p%d%d", i, j)}, "spec": map[string]any{"serviceAccountName": fmt.Sprint("sa", i), "automountServiceAccountToken": pod}})
		}
	}
	calls := 0
	fetch := func(path string) ([]byte, error) {
		calls++
		items := accounts
		if strings.HasPrefix(path, "/api/v1/pods?") {
			items = pods
		}
		b, _ := json.Marshal(items)
		return list(string(b), ""), nil
	}
	var out bytes.Buffer
	if err := Run("serviceaccounts", fetch, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// Existing shell audit: nil SA never passes; false SA accepts false/unset pod;
	// true SA accepts only false pod. Retain even surprising upstream behavior.
	expected := []bool{false, false, false, true, true, false, false, true, false}
	if len(lines) != 9 || calls != 2 {
		t.Fatalf("lines=%d calls=%d", len(lines), calls)
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, fmt.Sprint("is_compliant: ", expected[i])) {
			t.Fatal(line)
		}
	}
}

func TestFailuresNeverPublishPartialResults(t *testing.T) {
	for _, failure := range []string{"forbidden", "timeout", "expired continuation", "malformed", "missing items"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			fetch := func(string) ([]byte, error) {
				calls++
				if calls == 1 {
					return list(`[{"metadata":{"name":"read","namespace":"ns"},"rules":[]}]`, "next"), nil
				}
				if failure == "malformed" {
					return []byte("{"), nil
				}
				if failure == "missing items" {
					return []byte(`{"kind":"Status"}`), nil
				}
				return nil, fmt.Errorf("%s", failure)
			}
			var out bytes.Buffer
			if err := Run("roles", fetch, &out); err == nil {
				t.Fatal("expected error")
			}
			if out.Len() != 0 {
				t.Fatal("partial evidence leaked")
			}
		})
	}
}

func TestMissingServiceAccount(t *testing.T) {
	var out bytes.Buffer
	err := Run("serviceaccounts", func(path string) ([]byte, error) {
		if strings.HasPrefix(path, "/api/v1/serviceaccounts?") {
			return list(`[]`, ""), nil
		}
		return list(`[{"metadata":{"name":"p","namespace":"ns"},"spec":{"serviceAccountName":"missing"}}]`, ""), nil
	}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func Test8008RolesUse17Pages(t *testing.T) {
	calls := 0
	fetch := func(path string) ([]byte, error) {
		calls++
		u, _ := url.Parse(path)
		if strings.Contains(path, "/clusterroles?") {
			return list(`[]`, ""), nil
		}
		offset := 0
		if token := u.Query().Get("continue"); token != "" {
			fmt.Sscanf(token, "%d", &offset)
		}
		end := offset + 500
		if end > 8008 {
			end = 8008
		}
		var items []map[string]any
		for i := offset; i < end; i++ {
			items = append(items, map[string]any{"metadata": map[string]string{"name": fmt.Sprint("r", i), "namespace": "ns"}, "rules": []any{}})
		}
		token := ""
		if end < 8008 {
			token = fmt.Sprint(end)
		}
		b, _ := json.Marshal(items)
		return list(string(b), token), nil
	}
	var out bytes.Buffer
	if err := Run("roles", fetch, &out); err != nil {
		t.Fatal(err)
	}
	if calls != 18 || strings.Count(out.String(), "\n") != 8008 {
		t.Fatalf("calls=%d", calls)
	}
}

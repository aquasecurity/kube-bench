package cisaudit

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func TestAuthenticatedTLSAPI(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bearer token")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/api/v1/pods" || r.URL.Query().Get("continue") != "a+b/=" {
			t.Error(r.URL)
		}
		fmt.Fprint(w, `{"items":[]}`)
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	fetch, err := newAPIFetch(&rest.Config{Host: server.URL, BearerTokenFile: token, TLSClientConfig: rest.TLSClientConfig{CAData: ca}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fetch("/api/v1/pods?limit=500&continue=a%2Bb%2F%3D"); err != nil {
		t.Fatal(err)
	}
}

func TestAPIRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	fetch, err := newAPIFetch(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fetch("/api/v1/pods"); err == nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
}

func TestAPIHTTPFailures(t *testing.T) {
	for _, code := range []int{401, 403, 410, 500, 302} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(code)
			}))
			defer server.Close()
			fetch, err := newAPIFetch(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = fetch("/api/v1/pods"); err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestConfigSelection(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	content := `apiVersion: v1
kind: Config
current-context: test
clusters:
- name: test
  cluster:
    server: https://explicit.example
contexts:
- name: test
  context:
    cluster: test
    user: test
users:
- name: test
  user:
    token: test-token
`
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	rules := &clientcmd.ClientConfigLoadingRules{Precedence: []string{file}}
	t.Setenv("KUBECONFIG", file)
	config, err := loadConfig(rules, func() (*rest.Config, error) { t.Fatal("explicit config ignored"); return nil, nil })
	if err != nil || config.Host != "https://explicit.example" {
		t.Fatalf("config=%v err=%v", config, err)
	}
	t.Setenv("KUBECONFIG", "")
	config, err = loadConfig(rules, func() (*rest.Config, error) { return &rest.Config{Host: "https://incluster.example"}, nil })
	if err != nil || config.Host != "https://incluster.example" {
		t.Fatalf("config=%v err=%v", config, err)
	}
	_, err = loadConfig(rules, func() (*rest.Config, error) { return nil, fmt.Errorf("token unreadable") })
	if err == nil {
		t.Fatal("silently ignored broken pod credentials")
	}
	config, err = loadConfig(rules, func() (*rest.Config, error) { return nil, rest.ErrNotInCluster })
	if err != nil || config.Host != "https://explicit.example" {
		t.Fatalf("local config=%v err=%v", config, err)
	}
	rules.Precedence = []string{filepath.Join(t.TempDir(), "missing")}
	_, err = loadConfig(rules, func() (*rest.Config, error) { return nil, rest.ErrNotInCluster })
	if err == nil {
		t.Fatal("allowed localhost fallback")
	}
	t.Setenv("KUBECONFIG", "missing")
	_, err = loadConfig(rules, func() (*rest.Config, error) { t.Fatal("fell back despite explicit KUBECONFIG"); return nil, nil })
	if err == nil {
		t.Fatal("accepted missing explicit config")
	}
}

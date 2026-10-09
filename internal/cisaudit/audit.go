// Package cisaudit implements bounded-page collectors for CIS 1.12 policy audits.
package cisaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Fetch func(string) ([]byte, error)

type object struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Rules     json.RawMessage `json:"rules"`
	Automount *bool           `json:"automountServiceAccountToken"`
	Spec      struct {
		ServiceAccountName string `json:"serviceAccountName"`
		ServiceAccount     string `json:"serviceAccount"`
		Automount          *bool  `json:"automountServiceAccountToken"`
	} `json:"spec"`
}

func pages(fetch Fetch, path string, visit func(object) error) error {
	token := ""
	for {
		query := url.Values{"limit": {"500"}}
		if token != "" {
			query.Set("continue", token)
		}
		data, err := fetch(path + "?" + query.Encode())
		if err != nil {
			return err
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []object `json:"items"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		if page.Items == nil {
			return fmt.Errorf("API response for %s has no items array", path)
		}
		for _, item := range page.Items {
			if item.Metadata.Name == "" {
				return fmt.Errorf("unnamed object in %s", path)
			}
			if err := visit(item); err != nil {
				return err
			}
		}
		next := page.Metadata.Continue
		if next == "" {
			return nil
		}
		if next == token {
			return fmt.Errorf("repeated continuation token for %s", path)
		}
		token = next
	}
}

func value(v *bool) string {
	if v == nil {
		return "notset"
	}
	if *v {
		return "true"
	}
	return "false"
}

func cachePath(dir, ns, name string) string {
	return filepath.Join(dir, fmt.Sprintf("%x", sha256.Sum256([]byte(ns+"/"+name))))
}

// Run stages output on disk: failed collection never exposes partial PASS evidence.
// The evaluator still retains audit output, so this does not bound total kube-bench memory.
func Run(mode string, fetch Fetch, out io.Writer) error {
	if mode != "roles" && mode != "serviceaccounts" {
		return fmt.Errorf("unknown audit %q", mode)
	}
	dir, err := os.MkdirTemp("", "kube-bench-cis-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	report, err := os.CreateTemp(dir, "report-")
	if err != nil {
		return err
	}
	defer report.Close()
	if mode == "roles" {
		for _, kind := range []string{"roles", "clusterroles"} {
			err = pages(fetch, "/apis/rbac.authorization.k8s.io/v1/"+kind, func(o object) error {
				rules := o.Rules
				if len(rules) == 0 {
					rules = json.RawMessage("null")
				}
				var compact bytes.Buffer
				if err := json.Compact(&compact, rules); err != nil {
					return err
				}
				// Preserve the existing grep semantics, including its exact wildcard-array match.
				compliant := !strings.Contains(compact.String(), `["*"]`)
				if kind == "roles" {
					if o.Metadata.Namespace == "" {
						return fmt.Errorf("Role %s lacks namespace", o.Metadata.Name)
					}
					_, err := fmt.Fprintf(report, "**role_name: %s role_namespace: %s role_rules: %s role_is_compliant: %t\n", o.Metadata.Name, o.Metadata.Namespace, compact.String(), compliant)
					return err
				}
				_, err := fmt.Fprintf(report, "**clusterrole_name: %s clusterrole_rules: %s clusterrole_is_compliant: %t\n", o.Metadata.Name, compact.String(), compliant)
				return err
			})
			if err != nil {
				return err
			}
		}
	} else {
		err = pages(fetch, "/api/v1/serviceaccounts", func(o object) error {
			if o.Metadata.Namespace == "" {
				return fmt.Errorf("ServiceAccount %s lacks namespace", o.Metadata.Name)
			}
			return os.WriteFile(cachePath(dir, o.Metadata.Namespace, o.Metadata.Name), []byte(value(o.Automount)), 0600)
		})
		if err != nil {
			return err
		}
		err = pages(fetch, "/api/v1/pods", func(o object) error {
			name := o.Spec.ServiceAccountName
			if name == "" {
				name = o.Spec.ServiceAccount
			}
			if name == "" {
				name = "default"
			}
			sa, err := os.ReadFile(cachePath(dir, o.Metadata.Namespace, name))
			if err != nil {
				return fmt.Errorf("ServiceAccount %s/%s unavailable for pod %s: %w", o.Metadata.Namespace, name, o.Metadata.Name, err)
			}
			pod := value(o.Spec.Automount)
			// Deliberately retain the original CIS 1.12 truth table.
			compliant := (string(sa) == "false" && (pod == "false" || pod == "notset")) || (string(sa) == "true" && pod == "false")
			_, err = fmt.Fprintf(report, "**namespace: %s pod_name: %s service_account: %s pod_is_automountserviceaccounttoken: %s svacc_is_automountServiceAccountToken: %s is_compliant: %t\n", o.Metadata.Namespace, o.Metadata.Name, name, pod, sa, compliant)
			return err
		})
		if err != nil {
			return err
		}
	}
	if _, err := report.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = io.Copy(out, report)
	return err
}

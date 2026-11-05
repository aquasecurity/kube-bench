// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubKubectl installs a fake kubectl at the front of PATH that reproduces the
// failure reported in aquasecurity/kube-bench#1982: kubectl cannot reach the
// API server and prints a connection error instead of audit data
// (kubernetes/kubernetes#93474 - a client configuration flag makes kubectl drop
// its configuration and fall back to localhost:8080).
func stubKubectl(t *testing.T, stdout, stderr string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n"
	if stdout != "" {
		script += "cat <<'EOF'\n" + stdout + "\nEOF\n"
	}
	if stderr != "" {
		script += "cat >&2 <<'EOF'\n" + stderr + "\nEOF\n"
	}
	script += "exit " + map[int]string{0: "0", 1: "1"}[exitCode] + "\n"
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

const connectionRefused = "The connection to the server localhost:8080 was refused - did you specify the right host or port?"

// TestKubectlUnreachable_MustNotBeEvaluatedAsAuditData covers the cis-1.9
// policies checks named in #1982 (5.1.1, 5.1.2, 5.1.4): their audits wrap
// kubectl in echo/pipelines, so the command exits 0 and the connection error
// ends up in the audit output. It must not be scored as a compliance result.
func TestKubectlUnreachable_MustNotBeEvaluatedAsAuditData(t *testing.T) {
	stubKubectl(t, "", connectionRefused, 1)

	cases := []struct {
		name  string
		check Check
	}{
		{
			// 5.1.1: kubectl output piped into a while loop.
			name: "5.1.1 clusterrolebindings",
			check: Check{
				Scored: false,
				Audit: `kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name --no-headers | while read -r role_name
do
  echo "**role_name: ${role_name} is_compliant: true"
done`,
				Tests: &tests{TestItems: []*testItem{{
					Flag:    "is_compliant",
					Set:     true,
					Compare: compare{Op: "eq", Value: "true"},
				}}},
			},
		},
		{
			// 5.1.2: kubectl inside command substitution, echoed back.
			name: "5.1.2 can-i secrets",
			check: Check{
				Scored: false,
				Audit:  `echo "canGetListWatchSecretsAsSystemAuthenticated: $(kubectl auth can-i get,list,watch secrets --all-namespaces --as=system:authenticated)"`,
				Tests: &tests{TestItems: []*testItem{{
					Flag:    "canGetListWatchSecretsAsSystemAuthenticated",
					Set:     true,
					Compare: compare{Op: "eq", Value: "no"},
				}}},
			},
		},
		{
			// 5.1.4: same shape as 5.1.2.
			name: "5.1.4 can-i create pods",
			check: Check{
				Scored: true,
				Audit:  `echo "canCreatePodsAsSystemAuthenticated: $(kubectl auth can-i create pods --all-namespaces --as=system:authenticated)"`,
				Tests: &tests{TestItems: []*testItem{{
					Flag:    "canCreatePodsAsSystemAuthenticated",
					Set:     true,
					Compare: compare{Op: "eq", Value: "no"},
				}}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := tc.check.run()

			if state != WARN {
				t.Errorf("expected WARN when the API server is unreachable, got %s", state)
			}
			if tc.check.ActualValue != "" {
				t.Errorf("connection error must not be recorded as audit data, got actual value %q", tc.check.ActualValue)
			}
			if !strings.Contains(tc.check.Reason, "could not connect to the API server") {
				t.Errorf("expected a reason naming the connectivity failure, got %q", tc.check.Reason)
			}
			if !strings.Contains(tc.check.Reason, "localhost:8080 was refused") {
				t.Errorf("expected the reason to carry kubectl's error, got %q", tc.check.Reason)
			}
		})
	}
}

// TestKubectlReachable_CheckRunsNormally is the control case: when kubectl can
// reach the API server the audit is evaluated exactly as before.
func TestKubectlReachable_CheckRunsNormally(t *testing.T) {
	stubKubectl(t, "no", "", 0)

	c := Check{
		Scored: false,
		Audit:  `echo "canGetListWatchSecretsAsSystemAuthenticated: $(kubectl auth can-i get,list,watch secrets --all-namespaces --as=system:authenticated)"`,
		Tests: &tests{TestItems: []*testItem{{
			Flag:    "canGetListWatchSecretsAsSystemAuthenticated",
			Set:     true,
			Compare: compare{Op: "eq", Value: "no"},
		}}},
	}

	state := c.run()
	if state != PASS {
		t.Errorf("expected PASS when kubectl answers, got %s (reason %q)", state, c.Reason)
	}
	if c.Reason != "" {
		t.Errorf("expected no reason on a successful audit, got %q", c.Reason)
	}
	if !strings.Contains(c.ActualValue, "canGetListWatchSecretsAsSystemAuthenticated: no") {
		t.Errorf("expected the audit output as actual value, got %q", c.ActualValue)
	}
}

// TestKubectlUnreachable_NonKubectlAuditUntouched guards the scope of the
// detection: an audit that does not invoke kubectl is evaluated as before even
// if its output happens to contain a connection error line.
func TestKubectlUnreachable_NonKubectlAuditUntouched(t *testing.T) {
	c := Check{
		Scored: false,
		Audit:  `echo "hello The connection to the server localhost:8080 was refused - did you specify the right host or port?"`,
		Tests: &tests{TestItems: []*testItem{{
			Flag: "hello",
			Set:  true,
		}}},
	}

	state := c.run()
	if state != PASS {
		t.Errorf("expected PASS for a non-kubectl audit, got %s", state)
	}
	if c.Reason != "" {
		t.Errorf("expected no reason for a non-kubectl audit, got %q", c.Reason)
	}
}

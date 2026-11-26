// Copyright © 2026 Aqua Security Software Ltd. <info@aquasec.com>
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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

// runCheckFromYAML unmarshals a check definition and runs it exactly as the
// default runner does.
func runCheckFromYAML(t *testing.T, spec string) (State, *Check) {
	t.Helper()
	c := &Check{}
	if err := yaml.Unmarshal([]byte(spec), c); err != nil {
		t.Fatalf("failed to unmarshal check: %v", err)
	}
	return c.run(), c
}

// TestNotApplicableWhenAuditReportsMissingFile reproduces the RKE2 case where
// the audited etcd/kubelet file does not exist. The check must be reported as
// Not Applicable rather than PASS (via a "not found" sentinel test item) or FAIL.
func TestNotApplicableWhenAuditReportsMissingFile(t *testing.T) {
	spec := `
id: 4.1.9
text: "If the kubelet config.yaml configuration file is being used validate permissions"
scored: true
na_if_missing: true
audit: |
  /bin/sh -c 'if test -e /nonexistent-kube-bench-rke2/kubelet.conf; then
     stat -c "permissions=%a" /nonexistent-kube-bench-rke2/kubelet.conf
   else
     echo "File not found"
   fi'
tests:
  bin_op: or
  test_items:
    - flag: "permissions"
      compare:
        op: bitmask
        value: "600"
      set: true
    - flag: "File not found"
`
	state, c := runCheckFromYAML(t, spec)
	if string(state) != "NA" {
		t.Errorf("expected state NA for a missing kubelet config file, got %s (actual=%q reason=%q)", state, c.ActualValue, c.Reason)
	}
}

// TestNotApplicableWhenAuditProducesNoOutput covers benchmark definitions whose
// audit command is guarded by `test -e` with no else branch: a missing file
// produces no output at all, which currently results in FAIL for scored checks.
func TestNotApplicableWhenAuditProducesNoOutput(t *testing.T) {
	spec := `
id: 1.1.7
text: "Ensure that the etcd pod specification file permissions are set"
scored: true
na_if_missing: true
audit: "/bin/sh -c 'if test -e /nonexistent-kube-bench-rke2/etcd.yaml; then stat -c permissions=%a /nonexistent-kube-bench-rke2/etcd.yaml; fi'"
tests:
  test_items:
    - flag: "permissions"
      compare:
        op: bitmask
        value: "600"
      set: true
`
	state, c := runCheckFromYAML(t, spec)
	if string(state) != "NA" {
		t.Errorf("expected state NA when audit output is empty, got %s (actual=%q reason=%q)", state, c.ActualValue, c.Reason)
	}
}

// TestApplicableCheckStillEvaluated guards against the NA handling masking real
// failures: when the audited file exists, the normal test result must be used.
func TestApplicableCheckStillEvaluated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubelet.conf")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := fmt.Sprintf(`
id: 4.1.9
text: "kubelet config permissions"
scored: true
na_if_missing: true
audit: "/bin/sh -c 'if test -e %s; then stat -c permissions=%%a %s; else echo \"File not found\"; fi'"
tests:
  test_items:
    - flag: "permissions"
      compare:
        op: bitmask
        value: "600"
      set: true
`, path, path)
	state, c := runCheckFromYAML(t, spec)
	if state != PASS {
		t.Errorf("expected PASS for an existing compliant file, got %s (actual=%q reason=%q)", state, c.ActualValue, c.Reason)
	}
}

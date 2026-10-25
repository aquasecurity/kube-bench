// Copyright © 2017-2020 Aqua Security Software Ltd. <info@aquasec.com>
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
	"strings"
	"testing"
)

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		name     string
		check    Check
		Expected State
	}

	testCases := []TestCase{
		{name: "Manual check should WARN", check: Check{Type: MANUAL}, Expected: WARN},
		{name: "Skip check should INFO", check: Check{Type: "skip"}, Expected: INFO},
		{name: "Unscored check (with no type) should WARN on failure", check: Check{Scored: false}, Expected: WARN},
		{
			name: "Unscored check that pass should PASS",
			check: Check{
				Scored: false,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},

		{name: "Check with no tests should WARN", check: Check{Scored: true}, Expected: WARN},
		{name: "Scored check with empty tests should FAIL", check: Check{Scored: true, Tests: &tests{}}, Expected: FAIL},
		{
			name: "Scored check that doesn't pass should FAIL",
			check: Check{
				Scored: true,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  false,
				}}},
			},
			Expected: FAIL,
		},
		{
			name: "Scored checks that pass should PASS",
			check: Check{
				Scored: true,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},
		{
			name: "Scored checks that pass should PASS when config file is not present",
			check: Check{
				Scored:      true,
				Audit:       "echo hello",
				AuditConfig: "/test/config.yaml",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},
		{
			name: "Scored checks that pass should FAIL when config file is not present",
			check: Check{
				Scored:      true,
				AuditConfig: "/test/config.yaml",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: FAIL,
		},
		{
			// A file permission check whose audit guards against a missing
			// file succeeds with no output when the file is absent, which no
			// test_item can match. See issue #1881.
			name: "File permission check FAILs for a missing file when the audit hides it",
			check: Check{
				Scored: true,
				Audit:  "/bin/sh -c 'if test -e /no/such/file; then stat -c permissions=%a /no/such/file; fi'",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "permissions",
					Set:  true,
					Compare: compare{
						Op:    "bitmask",
						Value: "600",
					},
				}}},
			},
			Expected: FAIL,
		},
		{
			// A bare stat exits non-zero for a missing file, so the check
			// FAILs on the error path before any test_item is evaluated. The
			// state is the same as above; what differs is that stat gets to
			// say why, which the next test asserts.
			name: "File permission check FAILs for a missing file with a bare stat",
			check: Check{
				Scored: true,
				Audit:  "/bin/sh -c 'stat -c permissions=%a /no/such/file'",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "permissions",
					Set:  true,
					Compare: compare{
						Op:    "bitmask",
						Value: "600",
					},
				}}},
			},
			Expected: FAIL,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.check.run()
			if testCase.check.State != testCase.Expected {
				t.Errorf("expected %s, actual %s", testCase.Expected, testCase.check.State)
			}
		})
	}
}

// The point of running stat directly rather than behind `if test -e` is not
// the state - a missing file FAILs either way - but whether kube-bench can
// say why. The guarded audit succeeds with no output and leaves nothing to
// report; the bare one exits non-zero and runAudit carries stat's own
// message into the check's Reason (stderr is collected together with stdout).
func TestCheck_RunSaysWhyAFilePermissionCheckFailed(t *testing.T) {
	permissions := func() *tests {
		return &tests{TestItems: []*testItem{{
			Flag:    "permissions",
			Set:     true,
			Compare: compare{Op: "bitmask", Value: "600"},
		}}}
	}

	guarded := Check{
		ID:     "guarded",
		Scored: true,
		Audit:  "/bin/sh -c 'if test -e /no/such/file; then stat -c permissions=%a /no/such/file; fi'",
		Tests:  permissions(),
	}
	if state := guarded.run(); state != FAIL {
		t.Errorf("guarded audit: expected %s, got %s", FAIL, state)
	}
	if guarded.Reason != "" || guarded.ActualValue != "" {
		t.Errorf("guarded audit: expected nothing to report, got reason %q and actual value %q",
			guarded.Reason, guarded.ActualValue)
	}

	bare := Check{
		ID:     "bare",
		Scored: true,
		Audit:  "/bin/sh -c 'stat -c permissions=%a /no/such/file'",
		Tests:  permissions(),
	}
	if state := bare.run(); state != FAIL {
		t.Errorf("bare audit: expected %s, got %s", FAIL, state)
	}
	if !strings.Contains(bare.Reason, "No such file or directory") {
		t.Errorf("bare audit: expected the reason to name the missing file, got %q", bare.Reason)
	}
}

func TestCheckAuditEnv(t *testing.T) {
	passingCases := []*Check{
		controls.Groups[2].Checks[0],
		controls.Groups[2].Checks[2],
		controls.Groups[2].Checks[3],
		controls.Groups[2].Checks[4],
	}

	failingCases := []*Check{
		controls.Groups[2].Checks[1],
		controls.Groups[2].Checks[5],
		controls.Groups[2].Checks[6],
	}

	for _, c := range passingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "PASS" {
				t.Errorf("Should PASS, got: %v", c.State)
			}
		})
	}

	for _, c := range failingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "FAIL" {
				t.Errorf("Should FAIL, got: %v", c.State)
			}
		})
	}
}

func TestCheckAuditConfig(t *testing.T) {
	passingCases := []*Check{
		controls.Groups[1].Checks[0],
		controls.Groups[1].Checks[3],
		controls.Groups[1].Checks[5],
		controls.Groups[1].Checks[7],
		controls.Groups[1].Checks[9],
		controls.Groups[1].Checks[15],
	}

	failingCases := []*Check{
		controls.Groups[1].Checks[1],
		controls.Groups[1].Checks[2],
		controls.Groups[1].Checks[4],
		controls.Groups[1].Checks[6],
		controls.Groups[1].Checks[8],
		controls.Groups[1].Checks[10],
		controls.Groups[1].Checks[11],
		controls.Groups[1].Checks[12],
		controls.Groups[1].Checks[13],
		controls.Groups[1].Checks[14],
		controls.Groups[1].Checks[16],
	}

	for _, c := range passingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "PASS" {
				t.Errorf("Should PASS, got: %v", c.State)
			}
		})
	}

	for _, c := range failingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "FAIL" {
				t.Errorf("Should FAIL, got: %v", c.State)
			}
		})
	}
}

func Test_runAudit(t *testing.T) {
	type args struct {
		audit  string
		output string
	}
	tests := []struct {
		name   string
		args   args
		errMsg string
		output string
	}{
		{
			name: "run success",
			args: args{
				audit: "echo 'hello world'",
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run multiple lines script",
			args: args{
				audit: `
hello() {
  echo "hello world"
}

hello
`,
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run failed",
			args: args{
				audit: "unknown_command",
			},
			errMsg: "failed to run: \"unknown_command\", output: \"/bin/sh: ",
			output: "not found\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errMsg string
			output, err := runAudit(tt.args.audit)
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != "" && !strings.Contains(errMsg, tt.errMsg) {
				t.Errorf("name %s errMsg = %q, want %q", tt.name, errMsg, tt.errMsg)
			}
			if errMsg == "" && output != tt.output {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
			if errMsg != "" && !strings.Contains(output, tt.output) {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
		})
	}
}

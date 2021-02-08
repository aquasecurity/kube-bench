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

func TestCheckAuditEnv(t *testing.T){
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

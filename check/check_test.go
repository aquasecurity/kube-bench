// Copyright © 2017-2019 Aqua Security Software Ltd. <info@aquasec.com>
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
	"os/exec"
	"testing"
)

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		check    Check
		Expected State
	}

	testCases := []TestCase{
		{check: Check{Type: MANUAL}, Expected: WARN},
		{check: Check{Type: "skip"}, Expected: INFO},

		{check: Check{Scored: false}, Expected: WARN}, // Not scored checks with no type, or not scored failing tests are marked warn
		{
			check: Check{ // Not scored checks with passing tests are marked pass
				Scored: false,
				Audit:  ":", Commands: []*exec.Cmd{exec.Command("")},
				Tests: &tests{TestItems: []*testItem{&testItem{}}},
			},
			Expected: PASS,
		},

		{check: Check{Scored: true}, Expected: WARN},                  // If there are no tests in the check, warn
		{check: Check{Scored: true, Tests: &tests{}}, Expected: FAIL}, // If there are tests that are not passing, fail
		{
			check: Check{ // Scored checks with passing tests are marked pass
				Scored: true,
				Audit:  ":", Commands: []*exec.Cmd{exec.Command("")},
				Tests: &tests{TestItems: []*testItem{&testItem{}}},
			},
			Expected: PASS,
		},
	}
	for _, testCase := range testCases {

		testCase.check.run()

		if testCase.check.State != testCase.Expected {
			t.Errorf("test failed, expected %s, actual %s\n", testCase.Expected, testCase.check.State)
		}
	}
}

func TestCheckAuditConfig(t *testing.T) {

	cases := []struct {
		*Check
		expected State
	}{
		{
			controls.Groups[1].Checks[0],
			"PASS",
		},
		{
			controls.Groups[1].Checks[1],
			"FAIL",
		},
		{
			controls.Groups[1].Checks[2],
			"FAIL",
		},
		{
			controls.Groups[1].Checks[3],
			"PASS",
		},
		{
			controls.Groups[1].Checks[4],
			"FAIL",
		},
		{
			controls.Groups[1].Checks[5],
			"PASS",
		},
		{
			controls.Groups[1].Checks[6],
			"FAIL",
		},
		{
			controls.Groups[1].Checks[7],
			"PASS",
		},
		{
			controls.Groups[1].Checks[8],
			"FAIL",
		},
	}

	for _, c := range cases {
		c.run()
		if c.State != c.expected {
			t.Errorf("%s, expected:%v, got:%v\n", c.Text, c.expected, c.State)
		}
	}
}

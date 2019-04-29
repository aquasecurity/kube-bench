package check

import (
	"testing"
)

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		check    Check
		Expected State
	}

	testCases := []TestCase{
		{check: Check{Type: "manual"}, Expected: WARN},
		{check: Check{Type: "skip"}, Expected: INFO},
		{check: Check{Type: "", Scored: false}, Expected: WARN}, // Not scored checks with no type should be marked warn
		{check: Check{Type: "", Scored: true}, Expected: WARN},  // If there are no tests in the check, warn
		{check: Check{Type: "manual", Scored: false}, Expected: WARN},
		{check: Check{Type: "skip", Scored: false}, Expected: INFO},
	}

	for _, testCase := range testCases {

		testCase.check.run()

		if testCase.check.State != testCase.Expected {
			t.Errorf("test failed, expected %s, actual %s\n", testCase.Expected, testCase.check.State)
		}
	}
}

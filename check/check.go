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
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/golang/glog"
)

// NodeType indicates the type of node (master, node).
type NodeType string

// State is the state of a control check.
type State string

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL State = "FAIL"
	// WARN could not carry out check.
	WARN State = "WARN"
	// INFO informational message
	INFO State = "INFO"

	// MASTER a master node
	MASTER NodeType = "master"
	// NODE a node
	NODE NodeType = "node"
	// FEDERATED a federated deployment.
	FEDERATED NodeType = "federated"

	// ETCD an etcd node
	ETCD NodeType = "etcd"
	// CONTROLPLANE a control plane node
	CONTROLPLANE NodeType = "controlplane"
	// POLICIES a node to run policies from
	POLICIES NodeType = "policies"
	// MANAGEDSERVICES a node to run managedservices from
	MANAGEDSERVICES = "managedservices"

	// MANUAL Check Type
	MANUAL string = "manual"
)

// Check contains information about a recommendation in the
// CIS Kubernetes document.
type Check struct {
	ID             string   `yaml:"id" json:"test_number"`
	Text           string   `json:"test_desc"`
	Audit          string   `json:"audit"`
	AuditConfig    string   `yaml:"audit_config"`
	Type           string   `json:"type"`
	Tests          *tests   `json:"omit"`
	Set            bool     `json:"omit"`
	Remediation    string   `json:"remediation"`
	TestInfo       []string `json:"test_info"`
	State          `json:"status"`
	ActualValue    string `json:"actual_value"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `yaml:"use_multiple_values"`
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason,omitempty"`
}

// Runner wraps the basic Run method.
type Runner interface {
	// Run runs a given check and returns the execution state.
	Run(c *Check) State
}

// NewRunner constructs a default Runner.
func NewRunner() Runner {
	return &defaultRunner{}
}

type defaultRunner struct{}

func (r *defaultRunner) Run(c *Check) State {
	return c.run()
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) run() State {

	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if c.Scored && len(strings.TrimSpace(c.Type)) == 0 && c.Tests == nil {
		c.Reason = "There are no tests"
		c.State = WARN
		return c.State
	}

	// If check type is skip, force result to INFO
	if c.Type == "skip" {
		c.Reason = "Test marked as skip"
		c.State = INFO
		return c.State
	}

	// If check type is manual force result to WARN
	if c.Type == MANUAL {
		c.Reason = "Test marked as a manual test"
		c.State = WARN
		return c.State
	}

	lastCommand := c.Audit
	hasAuditConfig := c.AuditConfig != ""

	state, finalOutput, retErrmsgs := performTest(c.Audit, c.Tests, c.IsMultiple)
	if len(state) > 0 {
		c.Reason = retErrmsgs
		c.State = state
		return c.State
	}
	errmsgs := retErrmsgs

	// If something went wrong with the 'Audit' command
	// and an 'AuditConfig' command was provided, use it to
	// execute tests
	if (finalOutput == nil || !finalOutput.testResult) && hasAuditConfig {
		lastCommand = c.AuditConfig

		nItems := len(c.Tests.TestItems)
		// The reason we're creating a copy of the "tests"
		// is so that tests can executed
		// with the AuditConfig command
		// against the Path only
		currentTests := &tests{
			BinOp:     c.Tests.BinOp,
			TestItems: make([]*testItem, nItems),
		}

		for i := 0; i < nItems; i++ {
			ti := c.Tests.TestItems[i]
			nti := &testItem{
				// Path is used to test Command Param values
				// AuditConfig ==> Path
				Path:    ti.Path,
				Set:     ti.Set,
				Compare: ti.Compare,
			}
			currentTests.TestItems[i] = nti
		}

		state, finalOutput, retErrmsgs = performTest(c.AuditConfig, currentTests, c.IsMultiple)
		if len(state) > 0 {
			c.Reason = retErrmsgs
			c.State = state
			return c.State
		}
		errmsgs += retErrmsgs
	}

	if finalOutput != nil && finalOutput.testResult {
		c.State = PASS
		c.ActualValue = finalOutput.actualResult
		c.ExpectedResult = finalOutput.ExpectedResult
	} else {
		if c.Scored {
			c.State = FAIL
		} else {
			c.Reason = errmsgs
			c.State = WARN
		}
	}

	if finalOutput != nil {
		glog.V(3).Infof("Check.ID: %s Command: %q TestResult: %t State: %q \n", c.ID, lastCommand, finalOutput.testResult, c.State)
	} else {
		glog.V(3).Infof("Check.ID: %s Command: %q TestResult: <<EMPTY>> \n", c.ID, lastCommand)
	}

	if errmsgs != "" {
		glog.V(2).Info(errmsgs)
	}
	return c.State
}

func performTest(audit string, tests *tests, isMultipleOutput bool) (State, *testOutput, string) {
	if len(strings.TrimSpace(audit)) == 0 {
		return "", failTestItem("missing command"), "missing audit command"
	}

	var out bytes.Buffer
	errmsgs := runAudit(audit, &out)

	finalOutput := tests.execute(out.String(), isMultipleOutput)
	if finalOutput == nil {
		errmsgs += fmt.Sprintf("Final output is <<EMPTY>>. Failed to run: %s\n", audit)
	}

	return "", finalOutput, errmsgs
}

func runAudit(audit string, out *bytes.Buffer) string {
	errmsgs := ""

	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		errmsgs += fmt.Sprintf("failed to run: %q, output: %q, error: %s\n", audit, out.String(), err)
	}

	glog.V(3).Infof("Command %q - Output:\n\n %q\n - Error Messages:%q \n", audit, out.String(), errmsgs)
	return errmsgs
}

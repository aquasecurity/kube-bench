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

	// SKIP for when a check should be skipped.
	SKIP = "skip"

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
	ID                string   `yaml:"id" json:"test_number"`
	Text              string   `json:"test_desc"`
	Audit             string   `json:"audit"`
	AuditEnv          string   `yaml:"audit_env"`
	AuditConfig       string   `yaml:"audit_config"`
	Type              string   `json:"type"`
	Tests             *tests   `json:"-"`
	Set               bool     `json:"-"`
	Remediation       string   `json:"remediation"`
	TestInfo          []string `json:"test_info"`
	State             `json:"status"`
	ActualValue       string `json:"actual_value"`
	Scored            bool   `json:"scored"`
	IsMultiple        bool   `yaml:"use_multiple_values"`
	ExpectedResult    string `json:"expected_result"`
	Reason            string `json:"reason,omitempty"`
	AuditOutput       string `json:"-"`
	AuditEnvOutput    string `json:"-"`
	AuditConfigOutput string `json:"-"`
	DisableEnvTesting bool   `json:"-"`
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
	if c.Scored && strings.TrimSpace(c.Type) == "" && c.Tests == nil {
		c.Reason = "There are no tests"
		c.State = WARN
		return c.State
	}

	// If check type is skip, force result to INFO
	if c.Type == SKIP {
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

	// If there aren't any tests defined this is a FAIL or WARN
	if c.Tests == nil || len(c.Tests.TestItems) == 0 {
		c.Reason = "No tests defined"
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		return c.State
	}

	// Command line parameters override the setting in the config file, so if we get a good result from the Audit command that's all we need to run
	var finalOutput *testOutput
	var lastCommand string

	lastCommand, err := c.runAuditCommands()
	if err == nil {
		finalOutput, err = c.execute()
	}

	if finalOutput != nil {
		if finalOutput.testResult {
			c.State = PASS
		} else {
			if c.Scored {
				c.State = FAIL
			} else {
				c.State = WARN
			}
		}

		c.ActualValue = finalOutput.actualResult
		c.ExpectedResult = finalOutput.ExpectedResult
	}

	if err != nil {
		c.Reason = err.Error()
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
	}

	if finalOutput != nil {
		glog.V(3).Infof("Check.ID: %s Command: %q TestResult: %t State: %q \n", c.ID, lastCommand, finalOutput.testResult, c.State)
	} else {
		glog.V(3).Infof("Check.ID: %s Command: %q TestResult: <<EMPTY>> \n", c.ID, lastCommand)
	}

	if c.Reason != "" {
		glog.V(2).Info(c.Reason)
	}
	return c.State
}

func (c *Check) runAuditCommands() (lastCommand string, err error) {
	// Always run auditEnvOutput if needed
	if c.AuditEnv != "" {
		c.AuditEnvOutput, err = runAudit(c.AuditEnv)
		if err != nil {
			return c.AuditEnv, err
		}
	}

	// Run the audit command and auditConfig commands, if present
	c.AuditOutput, err = runAudit(c.Audit)
	if err != nil {
		return c.Audit, err
	}

	c.AuditConfigOutput, err = runAudit(c.AuditConfig)
	return c.AuditConfig, err
}

func (c *Check) execute() (finalOutput *testOutput, err error) {
	finalOutput = &testOutput{}

	ts := c.Tests
	res := make([]testOutput, len(ts.TestItems))
	expectedResultArr := make([]string, len(res))

	glog.V(3).Infof("%d tests", len(ts.TestItems))
	for i, t := range ts.TestItems {

		t.isMultipleOutput = c.IsMultiple

		// Try with the auditOutput first, and if that's not found, try the auditConfigOutput
		t.auditUsed = AuditCommand
		result := *(t.execute(c.AuditOutput))
    
		// Check for AuditConfigOutput only if AuditConfig is set
		if !result.flagFound && c.AuditConfig != "" {
			//t.isConfigSetting = true
			t.auditUsed = AuditConfig
			result = *(t.execute(c.AuditConfigOutput))
			if !result.flagFound && t.Env != "" {
				t.auditUsed = AuditEnv
				result = *(t.execute(c.AuditEnvOutput))
			}
		}

		if !result.flagFound && t.Env != "" {
			t.auditUsed = AuditEnv
			result = *(t.execute(c.AuditEnvOutput))
		}
		res[i] = result
		expectedResultArr[i] = res[i].ExpectedResult
	}

	var result bool
	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		glog.V(2).Info(fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp))
		finalOutput.actualResult = fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp)
		return finalOutput, fmt.Errorf("unknown binary operator for tests %s", ts.BinOp)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].testResult
		}
		// Generate an AND expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " AND ")

	case or:
		result = false
		for i := range res {
			result = result || res[i].testResult
		}
		// Generate an OR expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " OR ")
	}

	finalOutput.testResult = result
	finalOutput.actualResult = res[0].actualResult

	glog.V(3).Infof("Returning from execute on tests: finalOutput %#v", finalOutput)
	return finalOutput, nil
}

func runAudit(audit string) (output string, err error) {
	var out bytes.Buffer

	audit = strings.TrimSpace(audit)
	if len(audit) == 0 {
		return output, err
	}

	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	output = out.String()

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", audit, output, err)
	} else {
		glog.V(3).Infof("Command %q\n - Output:\n %q", audit, output)

	}
	return output, err
}

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
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/joncalhoun/pipe"
)

// NodeType indicates the type of node (master, node, federated).
type NodeType string

// State is the state of a control check.
type State string

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL = "FAIL"
	// WARN could not carry out check.
	WARN = "WARN"

	// MASTER a master node
	MASTER NodeType = "master"
	// NODE a node
	NODE NodeType = "node"
	// FEDERATED a federated deployment.
	FEDERATED NodeType = "federated"
)

// Check contains information about a recommendation in the
// CIS Kubernetes 1.6+ document.
type Check struct {
	ID          string `yaml:"id" json:"id"`
	Text        string
	Audit       string      `json:"omit"`
	Commands    []*exec.Cmd `json:"omit"`
	Tests       *tests      `json:"omit"`
	Set         bool        `json:"omit"`
	Remediation string
	State
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) Run() {
	var out string

	// Check if command exists or exit with WARN.
	for _, cmd := range c.Commands {
		_, err := exec.LookPath(cmd.Path)
		if err != nil {
			c.State = WARN
			return
		}
	}

	// Run commands.
	if len(c.Commands) == 0 {
		// Likely a warning message.
		c.State = WARN
		return
	}

	p, err := pipe.New(c.Commands...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: error creating command pipeline %s\n", err)
		os.Exit(1)
	}

	pr, pw := io.Pipe()
	p.Stdout = pw
	defer pw.Close()

	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start: error running audit command %s\n", err)
		os.Exit(1)
	}

	// Read output of command chain into string for check.
	go func() {
		defer pr.Close()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			out += scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "error accumulating  output %s\n", err)
			os.Exit(1)
		}
	}()

	if err := p.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "wait: error running audit command %s\n", err)
		os.Exit(1)
	}

	res := c.Tests.execute(out)
	if res {
		c.State = PASS
	} else {
		c.State = FAIL
	}
}

// textToCommand transforms a text representation of commands to be
// run into a slice of commands.
// TODO: Make this more robust.
func textToCommand(s string) []*exec.Cmd {
	cmds := []*exec.Cmd{}

	cp := strings.Split(s, "|")
	// fmt.Println("check.toCommand:", cp)

	for _, v := range cp {
		v = strings.Trim(v, " ")
		cs := strings.Split(v, " ")

		cmd := exec.Command(cs[0], cs[1:]...)
		cmds = append(cmds, cmd)
	}

	return cmds
}

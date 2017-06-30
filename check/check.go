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
	"io"
	"os"
	"os/exec"
	"strings"
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
	// INFO informational message
	INFO = "INFO"

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
	var out bytes.Buffer

	// Check if command exists or exit with WARN.
	for _, cmd := range c.Commands {
		_, err := exec.LookPath(cmd.Path)
		if err != nil {
			c.State = WARN
			return
		}
	}

	// Run commands.
	n := len(c.Commands)
	if n == 0 {
		// Likely a warning message.
		c.State = WARN
		return
	}

	// Each command runs,
	//   cmd0 out -> cmd1 in, cmd1 out -> cmd2 in ... cmdn out -> os.stdout
	//   cmd0 err should terminate chain
	cs := c.Commands

	cs[0].Stderr = os.Stderr
	cs[n-1].Stdout = &out
	i := 1

	for _, v := range cs {
		fmt.Println(v.Args)
	}

	var err error
	for i < n {
		cs[i-1].Stdout, err = cs[i].StdinPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", cs[i].Path, err)
			os.Exit(1)
		}

		cs[i].Stderr = os.Stderr
		i++
	}

	i = 0
	for i < n {
		err := cs[i].Start()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", cs[i].Args, err)
			os.Exit(1)
		}

		errw := cs[i].Wait()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", cs[i].Args, errw)
			os.Exit(1)
		}

		if i < n-1 {
			cs[i].Stdout.(io.Closer).Close()
		}
		i++
	}

	res := c.Tests.execute(out.String())
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

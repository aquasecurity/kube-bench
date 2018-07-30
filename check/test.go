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
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// test:
// flag: OPTION
// set: (true|false)
// compare:
//   op: (eq|gt|gte|lt|lte|has)
//   value: val

type binOp string

const (
	and binOp = "and"
	or        = "or"
)

type testItem struct {
	Flag    string
	Output  string
	Value   string
	Set     bool
	Compare compare
}

type compare struct {
	Op    string
	Value string
}

type testOutput struct {
	testResult   bool
	actualResult string
}

func (t *testItem) execute(s string) *testOutput {
	result := &testOutput{}
	match := strings.Contains(s, t.Flag)

	if t.Set {
		var flagVal string
		isset := match

		if isset && t.Compare.Op != "" {
			// Expects flags in the form;
			// --flag=somevalue
			// --flag
			// somevalue
			//pttn := `(` + t.Flag + `)(=)*([^\s,]*) *`
			pttn := `(` + t.Flag + `)(=)*([^\s]*) *`
			flagRe := regexp.MustCompile(pttn)
			vals := flagRe.FindStringSubmatch(s)

			if len(vals) > 0 {
				if vals[3] != "" {
					flagVal = vals[3]
				} else {
					flagVal = vals[1]
				}
			} else {
				fmt.Fprintf(os.Stderr, "invalid flag in testitem definition")
				os.Exit(1)
			}

			result.actualResult = strings.ToLower(flagVal)
			switch t.Compare.Op {
			case "eq":
				value := strings.ToLower(flagVal)
				// Do case insensitive comparaison for booleans ...
				if value == "false" || value == "true" {
					result.testResult = value == t.Compare.Value
				} else {
					result.testResult = flagVal == t.Compare.Value
				}

			case "noteq":
				value := strings.ToLower(flagVal)
				// Do case insensitive comparaison for booleans ...
				if value == "false" || value == "true" {
					result.testResult = !(value == t.Compare.Value)
				} else {
					result.testResult = !(flagVal == t.Compare.Value)
				}

			case "gt":
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a > b

			case "gte":
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a >= b

			case "lt":
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a < b

			case "lte":
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a <= b

			case "has":
				result.testResult = strings.Contains(flagVal, t.Compare.Value)

			case "nothave":
				result.testResult = !strings.Contains(flagVal, t.Compare.Value)
			}
		} else {
			result.testResult = isset
		}

	} else {
		notset := !match
		result.testResult = notset
	}
	return result
}

type tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

func (ts *tests) execute(s string) *testOutput {
	res := make([]testOutput, len(ts.TestItems))

	for i, t := range ts.TestItems {
		res[i] = *(t.execute(s))
	}

	var result bool
	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		fmt.Fprintf(os.Stderr, "unknown binary operator for tests %s\n", ts.BinOp)
		os.Exit(1)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].testResult
		}
	case or:
		result = false
		for i := range res {
			result = result || res[i].testResult
		}
	}
	finalOutput := &testOutput {
		testResult:   result,
		actualResult: res[0].actualResult
	}

	return finalOutput
}

func toNumeric(a, b string) (c, d int) {
	var err error
	c, err = strconv.Atoi(a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting %s: %s\n", a, err)
		os.Exit(1)
	}
	d, err = strconv.Atoi(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting %s: %s\n", b, err)
		os.Exit(1)
	}

	return c, d
}

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
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v2"
	"k8s.io/client-go/util/jsonpath"
)

// test:
// flag: OPTION
// set: (true|false)
// compare:
//   op: (eq|gt|gte|lt|lte|has)
//   value: val

type binOp string

const (
	and                   binOp = "and"
	or                          = "or"
	defaultArraySeperator       = ","
)

type testItem struct {
	Flag    string
	Path    string
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
	testResult     bool
	actualResult   string
	ExpectedResult string
}

func failTestItem(s string) *testOutput {
	return &testOutput{testResult: false, actualResult: s}
}

func (t *testItem) execute(s string) *testOutput {
	result := &testOutput{}
	var match bool
	var flagVal string

	if t.Flag != "" {
		// Flag comparison: check if the flag is present in the input
		match = strings.Contains(s, t.Flag)
	} else {
		// Path != "" - we don't know whether it's YAML or JSON but
		// we can just try one then the other
		var jsonInterface interface{}

		if t.Path != "" {
			err := unmarshal(s, &jsonInterface)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to load YAML or JSON from provided input \"%s\": %v\n", s, err)
				return failTestItem("failed to load YAML or JSON")
			}

		}

		jsonpathResult, err := executeJSONPath(t.Path, &jsonInterface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to parse path expression \"%s\": %v\n", t.Path, err)
			return failTestItem("error executing path expression")
		}
		match = (jsonpathResult != "")
		flagVal = jsonpathResult
	}

	if t.Set {
		isset := match

		if isset && t.Compare.Op != "" {
			if t.Flag != "" {
				// Expects flags in the form;
				// --flag=somevalue
				// flag: somevalue
				// --flag
				// somevalue
				pttn := `(` + t.Flag + `)(=|: *)*([^\s]*) *`
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
			}

			expectedResultPattern := ""
			switch t.Compare.Op {
			case "eq":
				expectedResultPattern = "'%s' is equal to '%s'"
				value := strings.ToLower(flagVal)
				// Do case insensitive comparaison for booleans ...
				if value == "false" || value == "true" {
					result.testResult = value == t.Compare.Value
				} else {
					result.testResult = flagVal == t.Compare.Value
				}

			case "noteq":
				expectedResultPattern = "'%s' is not equal to '%s'"
				value := strings.ToLower(flagVal)
				// Do case insensitive comparaison for booleans ...
				if value == "false" || value == "true" {
					result.testResult = !(value == t.Compare.Value)
				} else {
					result.testResult = !(flagVal == t.Compare.Value)
				}

			case "gt":
				expectedResultPattern = "%s is greater then %s"
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a > b

			case "gte":
				expectedResultPattern = "%s is greater or equal to %s"
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a >= b

			case "lt":
				expectedResultPattern = "%s is lower then %s"
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a < b

			case "lte":
				expectedResultPattern = "%s is lower or equal to %s"
				a, b := toNumeric(flagVal, t.Compare.Value)
				result.testResult = a <= b

			case "has":
				expectedResultPattern = "'%s' has '%s'"
				result.testResult = strings.Contains(flagVal, t.Compare.Value)

			case "nothave":
				expectedResultPattern = " '%s' not have '%s'"
				result.testResult = !strings.Contains(flagVal, t.Compare.Value)

			case "regex":
				expectedResultPattern = " '%s' matched by '%s'"
				opRe := regexp.MustCompile(t.Compare.Value)
				result.testResult = opRe.MatchString(flagVal)

			case "valid_elements":
				expectedResultPattern = " '%s' contains valid elements from '%s'"
				s := splitAndRemoveLastSeparator(flagVal, ",")
				target := splitAndRemoveLastSeparator(t.Compare.Value, ",")
				result.testResult = allElementsValid(s, target)

			}

			result.ExpectedResult = fmt.Sprintf(expectedResultPattern, t.Flag, t.Compare.Value)
		} else {
			result.ExpectedResult = fmt.Sprintf("'%s' is present", t.Flag)
			result.testResult = isset
		}
	} else {
		result.ExpectedResult = fmt.Sprintf("'%s' is not present", t.Flag)
		notset := !match
		result.testResult = notset
	}
	return result
}

func unmarshal(s string, jsonInterface *interface{}) error {
	data := []byte(s)
	err := json.Unmarshal(data, jsonInterface)
	if err != nil {
		err := yaml.Unmarshal(data, jsonInterface)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeJSONPath(path string, jsonInterface interface{}) (string, error) {
	j := jsonpath.New("jsonpath")
	j.AllowMissingKeys(true)
	err := j.Parse(path)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	err = j.Execute(buf, jsonInterface)
	if err != nil {
		return "", err
	}
	jsonpathResult := fmt.Sprintf("%s", buf)
	return jsonpathResult, nil
}

func allElementsValid(s, t []string) bool {
	if s == nil || len(s) == 0 {
		return false
	}
	for _, sv := range s {
		found := false
		for _, tv := range t {
			if sv == tv {
				found = true
				break
			}
		}
		if found == false {
			return false
		}
	}
	return true
}

func splitAndRemoveLastSeparator(s, sep string) []string {
	cleanS := strings.TrimRight(s, sep)
	if len(cleanS) == 0 {
		return []string{}
	}
	return strings.Split(cleanS, sep)
}

type tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

func (ts *tests) execute(s string) *testOutput {
	finalOutput := &testOutput{}

	// If no tests are defined return with empty finalOutput.
	// This may be the case for checks of type: "skip".
	if ts == nil {
		return finalOutput
	}

	res := make([]testOutput, len(ts.TestItems))
	if len(res) == 0 {
		return finalOutput
	}

	expectedResultArr := make([]string, len(res))

	for i, t := range ts.TestItems {
		res[i] = *(t.execute(s))
		expectedResultArr[i] = res[i].ExpectedResult
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

	if finalOutput.actualResult == "" {
		finalOutput.actualResult = s
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

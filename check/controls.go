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
	"encoding/xml"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/golang/glog"
	"github.com/onsi/ginkgo/reporters"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const (
	// UNKNOWN is when the AWS account can't be found
	UNKNOWN = "Unknown"
	// ARN for the AWS Security Hub service
	ARN = "arn:aws:securityhub:%s::product/aqua-security/kube-bench"
	// SCHEMA for the AWS Security Hub service
	SCHEMA = "2018-10-08"
	// TYPE is type of Security Hub finding
	TYPE = "Software and Configuration Checks/Industry and Regulatory Standards/CIS Kubernetes Benchmark"
)

type OverallControls struct {
	Controls []*Controls
	Totals   Summary
}

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID      string   `yaml:"id" json:"id"`
	Version string   `json:"version"`
	Text    string   `json:"text"`
	Type    NodeType `json:"node_type"`
	Groups  []*Group `json:"tests"`
	Summary
}

// Group is a collection of similar checks.
type Group struct {
	ID     string   `yaml:"id" json:"section"`
	Type   string   `yaml:"type" json:"type"`
	Pass   int      `json:"pass"`
	Fail   int      `json:"fail"`
	Warn   int      `json:"warn"`
	Info   int      `json:"info"`
	Text   string   `json:"desc"`
	Checks []*Check `json:"results"`
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

// Predicate a predicate on the given Group and Check arguments.
type Predicate func(group *Group, check *Check) bool

// NewControls instantiates a new master Controls object.
func NewControls(t NodeType, in []byte) (*Controls, error) {
	c := new(Controls)

	err := yaml.Unmarshal(in, c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %s", err)
	}

	if t != c.Type {
		return nil, fmt.Errorf("non-%s controls file specified", t)
	}

	return c, nil
}

// RunChecks runs the checks with the given Runner. Only checks for which the filter Predicate returns `true` will run.
func (controls *Controls) RunChecks(runner Runner, filter Predicate, skipIDMap map[string]bool) Summary {
	var g []*Group
	m := make(map[string]*Group)
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Info = 0, 0, 0, 0

	for _, group := range controls.Groups {
		for _, check := range group.Checks {

			if !filter(group, check) {
				continue
			}

			_, groupSkippedViaCmd := skipIDMap[group.ID]
			_, checkSkippedViaCmd := skipIDMap[check.ID]

			if group.Type == SKIP || groupSkippedViaCmd || checkSkippedViaCmd {
				check.Type = SKIP
			}

			state := runner.Run(check)

			check.TestInfo = append(check.TestInfo, check.Remediation)

			// Check if we have already added this checks group.
			if v, ok := m[group.ID]; !ok {
				// Create a group with same info
				w := &Group{
					ID:     group.ID,
					Text:   group.Text,
					Checks: []*Check{},
				}

				// Add this check to the new group
				w.Checks = append(w.Checks, check)
				summarizeGroup(w, state)

				// Add to groups we have visited.
				m[w.ID] = w
				g = append(g, w)
			} else {
				v.Checks = append(v.Checks, check)
				summarizeGroup(v, state)
			}

			summarize(controls, state)
		}
	}

	controls.Groups = g
	return controls.Summary
}

// JSON encodes the results of last run to JSON.
func (controls *Controls) JSON() ([]byte, error) {
	return json.Marshal(controls)
}

// JUnit encodes the results of last run to JUnit.
func (controls *Controls) JUnit() ([]byte, error) {
	suite := reporters.JUnitTestSuite{
		Name:      controls.Text,
		TestCases: []reporters.JUnitTestCase{},
		Tests:     controls.Summary.Pass + controls.Summary.Fail + controls.Summary.Info + controls.Summary.Warn,
		Failures:  controls.Summary.Fail,
	}
	for _, g := range controls.Groups {
		for _, check := range g.Checks {
			jsonCheck := ""
			jsonBytes, err := json.Marshal(check)
			if err != nil {
				jsonCheck = fmt.Sprintf("Failed to marshal test into JSON: %v. Test as text: %#v", err, check)
			} else {
				jsonCheck = string(jsonBytes)
			}
			tc := reporters.JUnitTestCase{
				Name:      fmt.Sprintf("%v %v", check.ID, check.Text),
				ClassName: g.Text,

				// Store the entire json serialization as system out so we don't lose data in cases where deeper debugging is necessary.
				SystemOut: jsonCheck,
			}

			switch check.State {
			case FAIL:
				tc.FailureMessage = &reporters.JUnitFailureMessage{Message: check.Remediation}
			case WARN, INFO:
				// WARN and INFO are two different versions of skipped tests. Either way it would be a false positive/negative to report
				// it any other way.
				tc.Skipped = &reporters.JUnitSkipped{}
			case PASS:
			default:
				glog.Warningf("Unrecognized state %s", check.State)
			}

			suite.TestCases = append(suite.TestCases, tc)
		}
	}

	var b bytes.Buffer
	encoder := xml.NewEncoder(&b)
	encoder.Indent("", "    ")
	err := encoder.Encode(suite)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate JUnit report: %s", err.Error())
	}

	return b.Bytes(), nil
}

// ASFF encodes the results of last run to AWS Security Finding Format(ASFF).
func (controls *Controls) ASFF() ([]*securityhub.AwsSecurityFinding, error) {
	fs := []*securityhub.AwsSecurityFinding{}
	a, err := getConfig("AWS_ACCOUNT")
	if err != nil {
		return nil, err
	}
	c, err := getConfig("CLUSTER_ARN")
	if err != nil {
		return nil, err
	}
	region, err := getConfig("AWS_REGION")
	if err != nil {
		return nil, err
	}
	arn := fmt.Sprintf(ARN, region)

	ti := time.Now()
	tf := ti.Format(time.RFC3339)
	for _, g := range controls.Groups {
		for _, check := range g.Checks {
			if check.State == FAIL || check.State == WARN {
				// ASFF ProductFields['Actual result'] can't be longer than 1024 characters
				actualValue := check.ActualValue
				if len(check.ActualValue) > 1024 {
					actualValue = check.ActualValue[0:1023]
				}
				f := securityhub.AwsSecurityFinding{
					AwsAccountId:  aws.String(a),
					Confidence:    aws.Int64(100),
					GeneratorId:   aws.String(fmt.Sprintf("%s/cis-kubernetes-benchmark/%s/%s", arn, controls.Version, check.ID)),
					Id:            aws.String(fmt.Sprintf("%s%sEKSnodeID+%s%s", arn, a, check.ID, tf)),
					CreatedAt:     aws.String(tf),
					Description:   aws.String(check.Text),
					ProductArn:    aws.String(arn),
					SchemaVersion: aws.String(SCHEMA),
					Title:         aws.String(fmt.Sprintf("%s %s", check.ID, check.Text)),
					UpdatedAt:     aws.String(tf),
					Types:         []*string{aws.String(TYPE)},
					Severity: &securityhub.Severity{
						Label: aws.String(securityhub.SeverityLabelHigh),
					},
					Remediation: &securityhub.Remediation{
						Recommendation: &securityhub.Recommendation{
							Text: aws.String(check.Remediation),
						},
					},
					ProductFields: map[string]*string{
						"Reason":          aws.String(check.Reason),
						"Actual result":   aws.String(actualValue),
						"Expected result": aws.String(check.ExpectedResult),
						"Section":         aws.String(fmt.Sprintf("%s %s", controls.ID, controls.Text)),
						"Subsection":      aws.String(fmt.Sprintf("%s %s", g.ID, g.Text)),
					},
					Resources: []*securityhub.Resource{
						{
							Id:   aws.String(c),
							Type: aws.String(TYPE),
						},
					},
				}
				fs = append(fs, &f)
			}
		}
	}
	return fs, nil
}
func getConfig(name string) (string, error) {
	r := viper.GetString(name)
	if len(r) == 0 {
		return "", fmt.Errorf("%s not set", name)
	}
	return r, nil
}
func summarize(controls *Controls, state State) {
	switch state {
	case PASS:
		controls.Summary.Pass++
	case FAIL:
		controls.Summary.Fail++
	case WARN:
		controls.Summary.Warn++
	case INFO:
		controls.Summary.Info++
	default:
		glog.Warningf("Unrecognized state %s", state)
	}
}

func summarizeGroup(group *Group, state State) {
	switch state {
	case PASS:
		group.Pass++
	case FAIL:
		group.Fail++
	case WARN:
		group.Warn++
	case INFO:
		group.Info++
	default:
		glog.Warningf("Unrecognized state %s", state)
	}
}

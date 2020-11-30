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
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/onsi/ginkgo/reporters"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/yaml.v2"
)

const cfgDir = "../cfg/"

type mockRunner struct {
	mock.Mock
}

func (m *mockRunner) Run(c *Check) State {
	args := m.Called(c)
	return args.Get(0).(State)
}

// validate that the files we're shipping are valid YAML
func TestYamlFiles(t *testing.T) {
	err := filepath.Walk(cfgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatalf("failure accessing path %q: %v\n", path, err)
		}
		if !info.IsDir() {
			t.Logf("reading file: %s", path)
			in, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("error opening file %s: %v", path, err)
			}

			c := new(Controls)
			err = yaml.Unmarshal(in, c)
			if err == nil {
				t.Logf("YAML file successfully unmarshalled: %s", path)
			} else {
				t.Fatalf("failed to load YAML from %s: %v", path, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failure walking cfg dir: %v\n", err)
	}
}

func TestNewControls(t *testing.T) {
	t.Run("Should return error when node type is not specified", func(t *testing.T) {
		// given
		in := []byte(`
---
controls:
type: # not specified
groups:
`)
		// when
		_, err := NewControls(MASTER, in)
		// then
		assert.EqualError(t, err, "non-master controls file specified")
	})

	t.Run("Should return error when input YAML is invalid", func(t *testing.T) {
		// given
		in := []byte("BOOM")
		// when
		_, err := NewControls(MASTER, in)
		// then
		assert.EqualError(t, err, "failed to unmarshal YAML: yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `BOOM` into check.Controls")
	})

}

func TestControls_RunChecks_SkippedCmd(t *testing.T) {
	t.Run("Should skip checks and groups specified by skipMap", func(t *testing.T) {
		// given
		normalRunner := &defaultRunner{}
		// and
		in := []byte(`
---
type: "master"
groups:
- id: G1
  checks:
  - id: G1/C1
  - id: G1/C2
  - id: G1/C3
- id: G2
  checks:
  - id: G2/C1
  - id: G2/C2
`)
		controls, err := NewControls(MASTER, in)
		assert.NoError(t, err)

		var allChecks Predicate = func(group *Group, c *Check) bool {
			return true
		}

		skipMap := make(map[string]bool, 0)
		skipMap["G1"] = true
		skipMap["G2/C1"] = true
		skipMap["G2/C2"] = true
		controls.RunChecks(normalRunner, allChecks, skipMap)

		G1 := controls.Groups[0]
		assertEqualGroupSummary(t, 0, 0, 3, 0, G1)

		G2 := controls.Groups[1]
		assertEqualGroupSummary(t, 0, 0, 2, 0, G2)
	})
}

func TestControls_RunChecks_Skipped(t *testing.T) {
	t.Run("Should skip checks where the parent group is marked as skip", func(t *testing.T) {
		// given
		normalRunner := &defaultRunner{}
		// and
		in := []byte(`
---
type: "master"
groups:
- id: G1
  skip: true
  checks:
  - id: G1/C1
`)
		controls, err := NewControls(MASTER, in)
		assert.NoError(t, err)

		var allChecks Predicate = func(group *Group, c *Check) bool {
			return true
		}
		emptySkipList := make(map[string]bool, 0)
		controls.RunChecks(normalRunner, allChecks, emptySkipList)

		G1 := controls.Groups[0]
		assertEqualGroupSummary(t, 0, 0, 1, 0, G1)
	})
}

func TestControls_RunChecks(t *testing.T) {
	t.Run("Should run checks matching the filter and update summaries", func(t *testing.T) {
		// given
		runner := new(mockRunner)
		// and
		in := []byte(`
---
type: "master"
groups:
- id: G1
  checks:
  - id: G1/C1
- id: G2
  checks:
  - id: G2/C1
    text: "Verify that the SomeSampleFlag argument is set to true"
    audit: "grep -B1 SomeSampleFlag=true /this/is/a/file/path"
    tests:
      test_items:
      - flag: "SomeSampleFlag=true"
        compare:
          op: has
          value: "true"
        set: true
    remediation: |
      Edit the config file /this/is/a/file/path and set SomeSampleFlag to true.
    scored: true
`)
		// and
		controls, err := NewControls(MASTER, in)
		assert.NoError(t, err)
		// and
		runner.On("Run", controls.Groups[0].Checks[0]).Return(PASS)
		runner.On("Run", controls.Groups[1].Checks[0]).Return(FAIL)
		// and
		var runAll Predicate = func(group *Group, c *Check) bool {
			return true
		}
		var emptySkipList = make(map[string]bool, 0)
		// when
		controls.RunChecks(runner, runAll, emptySkipList)
		// then
		assert.Equal(t, 2, len(controls.Groups))
		// and
		G1 := controls.Groups[0]
		assert.Equal(t, "G1", G1.ID)
		assert.Equal(t, "G1/C1", G1.Checks[0].ID)
		assertEqualGroupSummary(t, 1, 0, 0, 0, G1)
		// and
		G2 := controls.Groups[1]
		assert.Equal(t, "G2", G2.ID)
		assert.Equal(t, "G2/C1", G2.Checks[0].ID)
		assert.Equal(t, "has", G2.Checks[0].Tests.TestItems[0].Compare.Op)
		assert.Equal(t, "true", G2.Checks[0].Tests.TestItems[0].Compare.Value)
		assert.Equal(t, true, G2.Checks[0].Tests.TestItems[0].Set)
		assert.Equal(t, "SomeSampleFlag=true", G2.Checks[0].Tests.TestItems[0].Flag)
		assert.Equal(t, "Edit the config file /this/is/a/file/path and set SomeSampleFlag to true.\n", G2.Checks[0].Remediation)
		assert.Equal(t, true, G2.Checks[0].Scored)
		assertEqualGroupSummary(t, 0, 1, 0, 0, G2)
		// and
		assert.Equal(t, 1, controls.Summary.Pass)
		assert.Equal(t, 1, controls.Summary.Fail)
		assert.Equal(t, 0, controls.Summary.Info)
		assert.Equal(t, 0, controls.Summary.Warn)
		// and
		runner.AssertExpectations(t)
	})
}

func TestControls_JUnitIncludesJSON(t *testing.T) {
	testCases := []struct {
		desc   string
		input  *Controls
		expect []byte
	}{
		{
			desc: "Serializes to junit",
			input: &Controls{
				Groups: []*Group{
					{
						ID: "g1",
						Checks: []*Check{
							{ID: "check1id", Text: "check1text", State: PASS},
						},
					},
				},
			},
			expect: []byte(`<testsuite name="" tests="0" failures="0" errors="0" time="0">
    <testcase name="check1id check1text" classname="" time="0">
        <system-out>{&#34;test_number&#34;:&#34;check1id&#34;,&#34;test_desc&#34;:&#34;check1text&#34;,&#34;audit&#34;:&#34;&#34;,&#34;AuditEnv&#34;:&#34;&#34;,&#34;AuditConfig&#34;:&#34;&#34;,&#34;type&#34;:&#34;&#34;,&#34;remediation&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;PASS&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false,&#34;expected_result&#34;:&#34;&#34;}</system-out>
    </testcase>
</testsuite>`),
		}, {
			desc: "Summary values come from summary not checks",
			input: &Controls{
				Summary: Summary{
					Fail: 99,
					Pass: 100,
					Warn: 101,
					Info: 102,
				},
				Groups: []*Group{
					{
						ID: "g1",
						Checks: []*Check{
							{ID: "check1id", Text: "check1text", State: PASS},
						},
					},
				},
			},
			expect: []byte(`<testsuite name="" tests="402" failures="99" errors="0" time="0">
    <testcase name="check1id check1text" classname="" time="0">
        <system-out>{&#34;test_number&#34;:&#34;check1id&#34;,&#34;test_desc&#34;:&#34;check1text&#34;,&#34;audit&#34;:&#34;&#34;,&#34;AuditEnv&#34;:&#34;&#34;,&#34;AuditConfig&#34;:&#34;&#34;,&#34;type&#34;:&#34;&#34;,&#34;remediation&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;PASS&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false,&#34;expected_result&#34;:&#34;&#34;}</system-out>
    </testcase>
</testsuite>`),
		}, {
			desc: "Warn and Info are considered skips and failed tests properly reported",
			input: &Controls{
				Groups: []*Group{
					{
						ID: "g1",
						Checks: []*Check{
							{ID: "check1id", Text: "check1text", State: PASS},
							{ID: "check2id", Text: "check2text", State: INFO},
							{ID: "check3id", Text: "check3text", State: WARN},
							{ID: "check4id", Text: "check4text", State: FAIL},
						},
					},
				},
			},
			expect: []byte(`<testsuite name="" tests="0" failures="0" errors="0" time="0">
    <testcase name="check1id check1text" classname="" time="0">
        <system-out>{&#34;test_number&#34;:&#34;check1id&#34;,&#34;test_desc&#34;:&#34;check1text&#34;,&#34;audit&#34;:&#34;&#34;,&#34;AuditEnv&#34;:&#34;&#34;,&#34;AuditConfig&#34;:&#34;&#34;,&#34;type&#34;:&#34;&#34;,&#34;remediation&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;PASS&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false,&#34;expected_result&#34;:&#34;&#34;}</system-out>
    </testcase>
    <testcase name="check2id check2text" classname="" time="0">
        <skipped></skipped>
        <system-out>{&#34;test_number&#34;:&#34;check2id&#34;,&#34;test_desc&#34;:&#34;check2text&#34;,&#34;audit&#34;:&#34;&#34;,&#34;AuditEnv&#34;:&#34;&#34;,&#34;AuditConfig&#34;:&#34;&#34;,&#34;type&#34;:&#34;&#34;,&#34;remediation&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;INFO&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false,&#34;expected_result&#34;:&#34;&#34;}</system-out>
    </testcase>
    <testcase name="check3id check3text" classname="" time="0">
        <skipped></skipped>
        <system-out>{&#34;test_number&#34;:&#34;check3id&#34;,&#34;test_desc&#34;:&#34;check3text&#34;,&#34;audit&#34;:&#34;&#34;,&#34;AuditEnv&#34;:&#34;&#34;,&#34;AuditConfig&#34;:&#34;&#34;,&#34;type&#34;:&#34;&#34;,&#34;remediation&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;WARN&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false,&#34;expected_result&#34;:&#34;&#34;}</system-out>
    </testcase>
    <testcase name="check4id check4text" classname="" time="0">
        <failure type=""></failure>
        <system-out>{&#34;test_number&#34;:&#34;check4id&#34;,&#34;test_desc&#34;:&#34;check4text&#34;,&#34;audit&#34;:&#34;&#34;,&#34;AuditEnv&#34;:&#34;&#34;,&#34;AuditConfig&#34;:&#34;&#34;,&#34;type&#34;:&#34;&#34;,&#34;remediation&#34;:&#34;&#34;,&#34;test_info&#34;:null,&#34;status&#34;:&#34;FAIL&#34;,&#34;actual_value&#34;:&#34;&#34;,&#34;scored&#34;:false,&#34;IsMultiple&#34;:false,&#34;expected_result&#34;:&#34;&#34;}</system-out>
    </testcase>
</testsuite>`),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			junitBytes, err := tc.input.JUnit()
			if err != nil {
				t.Fatalf("Failed to serialize to JUnit: %v", err)
			}

			var out reporters.JUnitTestSuite
			if err := xml.Unmarshal(junitBytes, &out); err != nil {
				t.Fatalf("Unable to deserialize from resulting JUnit: %v", err)
			}

			// Check that each check was serialized as json and stored as systemOut.
			for iGroup, group := range tc.input.Groups {
				for iCheck, check := range group.Checks {
					jsonBytes, err := json.Marshal(check)
					if err != nil {
						t.Fatalf("Failed to serialize to JUnit: %v", err)
					}

					if out.TestCases[iGroup*iCheck+iCheck].SystemOut != string(jsonBytes) {
						t.Errorf("Expected\n\t%v\n\tbut got\n\t%v",
							out.TestCases[iGroup*iCheck+iCheck].SystemOut,
							string(jsonBytes),
						)
					}
				}
			}

			if !bytes.Equal(junitBytes, tc.expect) {
				t.Errorf("Expected\n\t%v\n\tbut got\n\t%v",
					string(tc.expect),
					string(junitBytes),
				)
			}
		})
	}
}

func assertEqualGroupSummary(t *testing.T, pass, fail, info, warn int, actual *Group) {
	t.Helper()
	assert.Equal(t, pass, actual.Pass)
	assert.Equal(t, fail, actual.Fail)
	assert.Equal(t, info, actual.Info)
	assert.Equal(t, warn, actual.Warn)
}

func TestControls_ASFF(t *testing.T) {
	type fields struct {
		ID      string
		Version string
		Text    string
		Groups  []*Group
		Summary Summary
	}
	tests := []struct {
		name    string
		fields  fields
		want    []*securityhub.AwsSecurityFinding
		wantErr bool
	}{
		{
			name: "Test simple conversion",
			fields: fields{
				ID:      "test1",
				Version: "1",
				Text:    "test runnner",
				Summary: Summary{
					Fail: 99,
					Pass: 100,
					Warn: 101,
					Info: 102,
				},
				Groups: []*Group{
					{
						ID:   "g1",
						Text: "Group text",
						Checks: []*Check{
							{ID: "check1id",
								Text:           "check1text",
								State:          FAIL,
								Remediation:    "fix me",
								Reason:         "failed",
								ExpectedResult: "failed",
								ActualValue:    "failed",
							},
						},
					},
				}},
			want: []*securityhub.AwsSecurityFinding{
				{
					AwsAccountId:  aws.String("foo account"),
					Confidence:    aws.Int64(100),
					GeneratorId:   aws.String(fmt.Sprintf("%s/cis-kubernetes-benchmark/%s/%s", fmt.Sprintf(ARN, "somewhere"), "1", "check1id")),
					Description:   aws.String("check1text"),
					ProductArn:    aws.String(fmt.Sprintf(ARN, "somewhere")),
					SchemaVersion: aws.String(SCHEMA),
					Title:         aws.String(fmt.Sprintf("%s %s", "check1id", "check1text")),
					Types:         []*string{aws.String(TYPE)},
					Severity: &securityhub.Severity{
						Label: aws.String(securityhub.SeverityLabelHigh),
					},
					Remediation: &securityhub.Remediation{
						Recommendation: &securityhub.Recommendation{
							Text: aws.String("fix me"),
						},
					},
					ProductFields: map[string]*string{
						"Reason":          aws.String("failed"),
						"Actual result":   aws.String("failed"),
						"Expected result": aws.String("failed"),
						"Section":         aws.String(fmt.Sprintf("%s %s", "test1", "test runnner")),
						"Subsection":      aws.String(fmt.Sprintf("%s %s", "g1", "Group text")),
					},
					Resources: []*securityhub.Resource{
						{
							Id:   aws.String("foo Cluster"),
							Type: aws.String(TYPE),
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Set("AWS_ACCOUNT", "foo account")
			viper.Set("CLUSTER_ARN", "foo Cluster")
			viper.Set("AWS_REGION", "somewhere")
			controls := &Controls{
				ID:      tt.fields.ID,
				Version: tt.fields.Version,
				Text:    tt.fields.Text,
				Groups:  tt.fields.Groups,
				Summary: tt.fields.Summary,
			}
			got, _ := controls.ASFF()
			tt.want[0].CreatedAt = got[0].CreatedAt
			tt.want[0].UpdatedAt = got[0].UpdatedAt
			tt.want[0].Id = got[0].Id
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Controls.ASFF() = %v, want %v", got, tt.want)
			}
		})
	}
}

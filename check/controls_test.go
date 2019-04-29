package check

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

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

func TestControls_RunChecks(t *testing.T) {

	t.Run("Should run all checks", func(t *testing.T) {
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
`)
		// and
		controls, _ := NewControls(MASTER, in)
		// and
		runner.On("Run", controls.Groups[0].Checks[0]).Return(PASS)
		runner.On("Run", controls.Groups[1].Checks[0]).Return(FAIL)
		// and
		var runAll Predicate = func(group *Group, c *Check) bool {
			return true
		}
		// when
		controls.RunChecks(runner, runAll)
		// then
		assert.Equal(t, 2, len(controls.Groups))
		// and
		assert.Equal(t, "G1", controls.Groups[0].ID)
		assert.Equal(t, "G1/C1", controls.Groups[0].Checks[0].ID)
		// and
		assert.Equal(t, "G2", controls.Groups[1].ID)
		assert.Equal(t, "G2/C1", controls.Groups[1].Checks[0].ID)
		// and
		// TODO We can assert that group and controls summaries are updated.
		// and
		runner.AssertExpectations(t)
	})

}

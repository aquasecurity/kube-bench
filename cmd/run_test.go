package cmd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestGetTestYamlFiles(t *testing.T) {
	cases := []struct {
		name      string
		targets   []string
		benchmark string
		succeed   bool
		expCount  int
	}{
		{
			name:      "Specify two targets",
			targets:   []string{"one", "two"},
			benchmark: "benchmark",
			succeed:   true,
			expCount:  2,
		},
		{
			name:      "Specify a target that doesn't exist",
			targets:   []string{"one", "missing"},
			benchmark: "benchmark",
			succeed:   false,
		},
		{
			name:      "No targets specified - should return everything except config.yaml",
			targets:   []string{},
			benchmark: "benchmark",
			succeed:   true,
			expCount:  3,
		},
		{
			name:      "Specify benchmark that doesn't exist",
			targets:   []string{"one"},
			benchmark: "missing",
			succeed:   false,
		},
	}

	// Set up temp config directory
	var err error
	cfgDir, err = ioutil.TempDir("", "kube-bench-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory")
	}
	defer os.RemoveAll(cfgDir)

	d := filepath.Join(cfgDir, "benchmark")
	err = os.Mkdir(d, 0766)
	if err != nil {
		t.Fatalf("Failed to create temp dir")
	}

	// We never expect config.yaml to be returned
	for _, filename := range []string{"one.yaml", "two.yaml", "three.yaml", "config.yaml"} {
		err = ioutil.WriteFile(filepath.Join(d, filename), []byte("hello world"), 0666)
		if err != nil {
			t.Fatalf("error writing temp file %s: %v", filename, err)
		}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yamlFiles, err := getTestYamlFiles(c.targets, c.benchmark)
			if err != nil && c.succeed {
				t.Fatalf("Error %v", err)
			}

			if err == nil && !c.succeed {
				t.Fatalf("Expected failure")
			}

			if len(yamlFiles) != c.expCount {
				t.Fatalf("Expected %d, got %d", c.expCount, len(yamlFiles))
			}
		})
	}
}

func TestTranslate(t *testing.T) {
	cases := []struct {
		name     string
		original string
		expected string
	}{
		{
			name:     "keep",
			original: "controlplane",
			expected: "controlplane",
		},
		{
			name:     "translate",
			original: "worker",
			expected: "node",
		},
		{
			name:     "translateLower",
			original: "Worker",
			expected: "node",
		},
		{
			name:     "Lower",
			original: "ETCD",
			expected: "etcd",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ret := translate(c.original)
			if ret != c.expected {
				t.Fatalf("Expected %q, got %q", c.expected, ret)
			}
		})
	}
}

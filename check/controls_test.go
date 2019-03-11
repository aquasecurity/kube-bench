package check

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

const cfgDir = "../cfg/"

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

package check

import (
	"io/ioutil"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

const cfgDir = "../cfg/"

// validate that the files we're shipping are valid YAML
func TestYamlFiles(t *testing.T) {
	files, err := ioutil.ReadDir(cfgDir)
	if err != nil {
		t.Fatalf("error reading %s directory: %v", cfgDir, err)
	}
	for _, file := range files {
		fileName := file.Name()
		in, err := ioutil.ReadFile(cfgDir + fileName)
		if err != nil {
			t.Fatalf("error opening file %s: %v", fileName, err)
		}

		c := new(Controls)

		err = yaml.Unmarshal(in, c)
		if err != nil {
			t.Fatalf("failed to load YAML from %s: %v", fileName, err)
		}
	}
}

package check

import (
	"io/ioutil"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

const cfgDir = "../cfg/"

// validate that the files we're shipping are valid YAML
func TestYamlFiles(t *testing.T) {
	dirs := []string{"1.6/", "1.7/"}

	for _, dir := range dirs {
		dir = cfgDir + dir

		files, err := ioutil.ReadDir(dir)
		if err != nil {
			t.Fatalf("error reading %s directory: %v", dir, err)
		}

		for _, file := range files {

			fileName := file.Name()
			in, err := ioutil.ReadFile(dir + fileName)
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
}

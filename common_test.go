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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/bench-common/check"
)

func TestDefinitionFiles(t *testing.T) {
	cfgdir := "cfg"

	vers, err := getDirContent(cfgdir)
	if err != nil && err.Error() != "not a directory" {
		t.Errorf("unexpected error: %s\n", err)
	}

	for _, ver := range vers {
		files, err := getDirContent(filepath.Join(cfgdir, ver))
		if err != nil && err.Error() != "not a directory" {
			t.Errorf("unexpected error: %s\n", err)
		}

		for _, file := range files {
			def := filepath.Join(cfgdir, ver, file)
			in, err := ioutil.ReadFile(def)
			if err != nil {
				t.Errorf("unexpected error: %s\n", err)
			}

			_, err = check.NewControls([]byte(in))
			if err != nil {
				t.Errorf("unexpected error: %s\n", err)
			}
		}
	}

}

func getDirContent(name string) ([]string, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory")
	}

	d, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	files, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	return files, err
}

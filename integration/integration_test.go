// +build integration

package integration

import (
	"fmt"
	"testing"
)

func TestRunWithKind(t *testing.T) {
	cases := []struct {
		TestName      string
		KindCfg       string
		KubebenchYAML string
		ExpectError   bool
	}{
		{
			TestName:      "job",
			KindCfg:       "./testdata/add-tls-kind.yaml",
			KubebenchYAML: "../job.yaml",
			ExpectError:   false,
		},
		{
			TestName:      "job-node",
			KindCfg:       "./testdata/add-tls-kind.yaml",
			KubebenchYAML: "../job-node.yaml",
			ExpectError:   false,
		},
		{
			TestName:      "job-master",
			KindCfg:       "./testdata/add-tls-kind.yaml",
			KubebenchYAML: "../job-master.yaml",
			ExpectError:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.TestName, func(t *testing.T) {
			output, err := runWithKind(c.TestName, c.KindCfg, c.KubebenchYAML)
			fmt.Printf("CLUSTER %s \n\n %s", c.TestName, output)
			if err != nil {
				if !c.ExpectError {
					t.Fatalf("unexpected error while Loading config: %v", err)
				}
				return
			}

			if c.ExpectError {
				t.Fatalf("unexpected lack or error while Loading config")
			}
		})
	}
}

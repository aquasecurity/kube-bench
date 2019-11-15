// +build integration

package integration

import (
	"flag"
	"fmt"
	"testing"
	"time"
)

var kubebenchImg = flag.String("kubebenchImg", "aquasec/kube-bench:latest", "kube-bench image used as part of this test")

func TestRunWithKind(t *testing.T) {
	flag.Parse()
	fmt.Printf("kube-bench Container Image: %s\n", *kubebenchImg)
	timeout := time.Duration(10 * time.Minute)
	ticker := time.Duration(2 * time.Second)

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
			output, err := runWithKind(c.TestName, c.KindCfg, c.KubebenchYAML, *kubebenchImg, timeout, ticker)
			fmt.Printf("CLUSTER %s \n\n %s", c.TestName, output)
			if err != nil {
				if !c.ExpectError {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if c.ExpectError {
				t.Fatalf("unexpected lack or error while Loading config")
			}
		})
	}
}

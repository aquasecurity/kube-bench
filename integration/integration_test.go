// +build integration

package integration

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

var kubebenchImg = flag.String("kubebenchImg", "aquasec/kube-bench:latest", "kube-bench image used as part of this test")

func TestRunWithKind(t *testing.T) {
	flag.Parse()
	fmt.Printf("kube-bench Container Image: %s\n", *kubebenchImg)
	timeout := time.Duration(10 * time.Minute)
	ticker := time.Duration(2 * time.Second)

	mustMatch := func(expFname, data string) {
		d, err := ioutil.ReadFile(expFname)
		if err != nil {
			t.Error(err)
		}
		expectedData := strings.TrimSpace(string(d))
		data = strings.TrimSpace(data)
		if expectedData != data {
			t.Errorf("expected: %q\n\n Got %q\n\n", expectedData, data)
		}
	}

	cases := []struct {
		TestName      string
		KindCfg       string
		KubebenchYAML string
		ExpectedFile  string
		ExpectError   bool
	}{
		{
			TestName:      "job",
			KindCfg:       "./testdata/add-tls-kind.yaml",
			KubebenchYAML: "../job.yaml",
			ExpectedFile:  "./testdata/job.data",
			ExpectError:   false,
		},
		{
			TestName:      "job-node",
			KindCfg:       "./testdata/add-tls-kind.yaml",
			KubebenchYAML: "../job-node.yaml",
			ExpectedFile:  "./testdata/job-node.data",
			ExpectError:   false,
		},
		{
			TestName:      "job-master",
			KindCfg:       "./testdata/add-tls-kind.yaml",
			KubebenchYAML: "../job-master.yaml",
			ExpectedFile:  "./testdata/job-master.data",
			ExpectError:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.TestName, func(t *testing.T) {
			data, err := runWithKind(c.TestName, c.KindCfg, c.KubebenchYAML, *kubebenchImg, timeout, ticker)
			fmt.Printf("CLUSTER %s \n\n %s", c.TestName, data)
			if err != nil {
				if !c.ExpectError {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if c.ExpectError {
				t.Fatalf("unexpected lack or error while Loading config")
			} else {
				mustMatch(c.ExpectedFile, data)
			}
		})
	}
}

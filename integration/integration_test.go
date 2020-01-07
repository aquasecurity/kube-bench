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
var timeout = flag.Duration("timeout", 10*time.Minute, "Test Timeout")

func TestRunWithKind(t *testing.T) {
	flag.Parse()
	fmt.Printf("kube-bench Container Image: %s\n", *kubebenchImg)

	mustMatch := func(tc *testing.T, expFname, data string) {
		d, err := ioutil.ReadFile(expFname)
		if err != nil {
			tc.Error(err)
		}
		expectedData := strings.TrimSpace(string(d))
		data = strings.TrimSpace(data)
		if expectedData != data {
			tc.Errorf("expected: %q\n\n Got %q\n\n", expectedData, data)
		}
	}

	cases := []struct {
		TestName      string
		KubebenchYAML string
		ExpectedFile  string
		ExpectError   bool
	}{
		{
			TestName:      "kube-bench",
			KubebenchYAML: "../job.yaml",
			ExpectedFile:  "./testdata/job.data",
		},
		{
			TestName:      "kube-bench-node",
			KubebenchYAML: "../job-node.yaml",
			ExpectedFile:  "./testdata/job-node.data",
		},
		{
			TestName:      "kube-bench-master",
			KubebenchYAML: "../job-master.yaml",
			ExpectedFile:  "./testdata/job-master.data",
		},
	}
	ctx, err := setupCluster("kube-bench", "./testdata/add-tls-kind-k8s114.yaml", *timeout)
	if err != nil {
		t.Fatalf("failed to setup KIND cluster error: %v", err)
	}
	defer func() {
		ctx.Delete()
	}()

	if err := loadImageFromDocker(*kubebenchImg, ctx); err != nil {
		t.Fatalf("failed to load kube-bench image from Docker to KIND error: %v", err)
	}

	for _, c := range cases {
		t.Run(c.TestName, func(tc *testing.T) {
			data, err := runWithKind(ctx, c.TestName, c.KubebenchYAML, *kubebenchImg, *timeout)
			if err != nil {
				tc.Errorf("unexpected error: %v", err)
			}
			mustMatch(tc, c.ExpectedFile, data)
		})
	}

}

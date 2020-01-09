// +build integration

package integration

import (
	"bufio"
	"bytes"
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

	clientset, err := getClientSet(ctx.KubeConfigPath())
	if err != nil {
		t.Fatalf("failed to connect to Kubernetes cluster error: %v", err)
	}

	for _, c := range cases {
		t.Run(c.TestName, func(t *testing.T) {
			resultData, err := runWithKind(ctx, clientset, c.TestName, c.KubebenchYAML, *kubebenchImg, *timeout)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			c, err := ioutil.ReadFile(c.ExpectedFile)
			if err != nil {
				t.Error(err)
			}

			expectedData := strings.TrimSpace(string(c))
			resultData = strings.TrimSpace(resultData)
			if expectedData != resultData {
				t.Errorf("expected results\n\nExpected\t(<)\nResult\t(>)\n\n%s\n\n", generateDiff(expectedData, resultData))
			}
		})
	}
}

func generateDiff(source, target string) string {
	buf := new(bytes.Buffer)
	ss := bufio.NewScanner(strings.NewReader(source))
	ts := bufio.NewScanner(strings.NewReader(target))

	emptySource := false
	emptyTarget := false
	dataFrom := ""
	hasMoreData := func() bool {
		sourceScan := ss.Scan()
		targetScan := ts.Scan()
		if sourceScan && targetScan {
			dataFrom = "<>"
		}
		if !sourceScan {
			dataFrom = ">"
		}
		if !targetScan {
			dataFrom = "<"
		}
		return sourceScan || targetScan
	}

	for ln := 1; hasMoreData(); ln++ {
		switch dataFrom {
		case "<>":
			ll := ss.Text()
			rl := ts.Text()
			if ll != rl {
				fmt.Fprintf(buf, "line: %d\n", ln)
				fmt.Fprintf(buf, "< %s\n", ll)
				fmt.Fprintf(buf, "> %s\n", rl)
			}
		case "<":
			ll := ss.Text()
			if !emptyTarget {
				fmt.Fprintf(buf, "line: %d\n", ln)
			}
			fmt.Fprintf(buf, "< %s\n", ll)
			emptyTarget = true
		case ">":
			rl := ts.Text()
			if !emptySource {
				fmt.Fprintf(buf, "line: %d\n", ln)
			}
			fmt.Fprintf(buf, "> %s\n", rl)
			emptySource = true
		}
	}

	if emptySource {
		fmt.Fprintf(buf, "< [[NO MORE DATA]]")
	}

	if emptyTarget {
		fmt.Fprintf(buf, "> [[NO MORE DATA]]")
	}

	return buf.String()
}

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/fatih/color"
)

var (
	// Print colors
	colors = map[check.State]*color.Color{
		check.PASS: color.New(color.FgGreen),
		check.FAIL: color.New(color.FgRed),
		check.WARN: color.New(color.FgYellow),
		check.INFO: color.New(color.FgBlue),
	}
)

func handleError(err error, context string) (errmsg string) {
	if err != nil {
		errmsg = fmt.Sprintf("%s, error: %s\n", context, err)
	}
	return
}

func cleanIDs(list string) []string {
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	for _, id := range ids {
		id = strings.Trim(id, " ")
	}

	return ids
}

func verifyConf(confPath ...string) []string {
	var w []string
	for _, c := range confPath {
		if _, err := os.Stat(c); err != nil && os.IsNotExist(err) {
			w = append(w, fmt.Sprintf("config file %s does not exist\n", c))
		}
	}

	return w
}

func verifyBin(binPath ...string) []string {
	var w []string
	var binList string

	// Construct proc name for ps(1)
	for _, b := range binPath {
		binList += b + ","
	}
	binList = strings.Trim(binList, ",")

	// Run ps command
	cmd := exec.Command("ps", "-C", binList, "-o", "cmd", "--no-headers")
	out, err := cmd.Output()
	errmsgs += handleError(
		err,
		fmt.Sprintf("verifyBin: %s failed", binList),
	)

	// Actual verification
	for _, b := range binPath {
		matched := strings.Contains(string(out), b)

		if !matched {
			w = append(w, fmt.Sprintf("%s is not running\n", b))
		}
	}

	return w
}

func verifyKubeVersion(b string) []string {
	// These executables might not be on the user's path.
	// TODO! Check the version number using kubectl, which is more likely to be on the path.
	var w []string

	// Check version
	cmd := exec.Command(b, "--version")
	out, err := cmd.Output()
	errmsgs += handleError(
		err,
		fmt.Sprintf("verifyKubeVersion: failed\nCommand:%s", cmd.Args),
	)

	matched := strings.Contains(string(out), kubeVersion)
	if !matched {
		w = append(w, fmt.Sprintf("%s unsupported version\n", b))
	}

	return w
}

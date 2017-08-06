package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/fatih/color"
	"github.com/golang/glog"
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

func printWarn(msg string) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n",
		colors[check.WARN].Sprintf("%s", check.WARN),
		msg,
	)
}

func printWarn(msg string) string {
	return fmt.Sprintf("[%s] %s",
		colors[check.WARN].Sprintf("%s", check.WARN),
		msg,
	)
}

func exitWithError(err error) {
	fmt.Fprintf(os.Stderr, "\n%v\n", err)
	os.Exit(1)
}

func continueWithError(err error, msg string) string {
	if err != nil {
		glog.V(1).Info(err)
	}

	if msg != "" {
		fmt.Fprintf(os.Stderr, "%s\n", msg)
	}

	return ""
}

func cleanIDs(list string) []string {
	list = strings.Trim(list, ",")
	ids := strings.Split(list, ",")

	for _, id := range ids {
		id = strings.Trim(id, " ")
	}

	return ids
}

func verifyConf(confPath ...string) {
	var missing string

	for _, c := range confPath {
		if _, err := os.Stat(c); err != nil && os.IsNotExist(err) {
			continueWithError(err, "")
			missing += c + ", "
		}
	}

	if len(missing) > 0 {
		missing = strings.Trim(missing, ", ")
		printWarn(fmt.Sprintf("Missing kubernetes config files: %s", missing))
	}

}

func verifyBin(binPath ...string) {
	var binSlice []string
	var bin string
	var missing string
	var notRunning string

	// Construct proc name for ps(1)
	for _, b := range binPath {
		_, err := exec.LookPath(b)
		bin = bin + "," + b
		binSlice = append(binSlice, b)
		if err != nil {
			missing += b + ", "
			continueWithError(err, "")
		}
	}
	bin = strings.Trim(bin, ",")

	cmd := exec.Command("ps", "-C", bin, "-o", "cmd", "--no-headers")
	out, err := cmd.Output()
	if err != nil {
		continueWithError(fmt.Errorf("%s: %s", cmd.Args, err), "")
	}

	for _, b := range binSlice {
		matched := strings.Contains(string(out), b)

		if !matched {
			notRunning += b + ", "
		}
	}

	if len(missing) > 0 {
		missing = strings.Trim(missing, ", ")
		printWarn(fmt.Sprintf("Missing kubernetes binaries: %s", missing))
	}

	if len(notRunning) > 0 {
		notRunning = strings.Trim(notRunning, ", ")
		printWarn(fmt.Sprintf("Kubernetes binaries not running: %s", notRunning))
	}
}

func verifyKubeVersion(b string) {
	// These executables might not be on the user's path.
	// TODO! Check the version number using kubectl, which is more likely to be on the path.

	_, err := exec.LookPath(b)
	if err != nil {
		continueWithError(err, printfWarn("Kubernetes version check skipped"))
		return
	}

	cmd := exec.Command(b, "--version")
	out, err := cmd.Output()
	if err != nil {
		continueWithError(err, printfWarn("Kubernetes version check skipped"))
		return
	}

	matched := strings.Contains(string(out), kubeVersion)
	if !matched {
		printWarn(fmt.Sprintf("Unsupported kubernetes version: %s", out))
	}
}

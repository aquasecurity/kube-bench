package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
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

func printlnWarn(msg string) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n",
		colors[check.WARN].Sprintf("%s", check.WARN),
		msg,
	)
}

func sprintlnWarn(msg string) string {
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

// ps execs out to the ps command; it's separated into a function so we can write tests
func ps(proc string) string {
	cmd := exec.Command("ps", "-C", proc, "-o", "cmd", "--no-headers")
	out, err := cmd.Output()
	if err != nil {
		continueWithError(fmt.Errorf("%s: %s", cmd.Args, err), "")
	}

	return string(out)
}

// verifyBin checks that the binary specified is running
func verifyBin(bin string, psFunc func(string) string) bool {

	// Strip any quotes
	bin = strings.Trim(bin, "'\"")

	// bin could consist of more than one word
	// We'll search for running processes with the first word, and then check the whole
	// proc as supplied is included in the results
	proc := strings.Fields(bin)[0]
	out := psFunc(proc)

	return strings.Contains(out, bin)
}

type version struct {
	Server string
	Client string
}

func getKubeVersion() *version {
	ver := new(version)
	// These executables might not be on the user's path.
	_, err := exec.LookPath("kubectl")
	if err != nil {
		s := fmt.Sprintf("Kubernetes version check skipped with error %v", err)
		continueWithError(err, sprintlnWarn(s))
		return nil
	}

	cmd := exec.Command("kubectl", "version")
	out, err := cmd.Output()
	if err != nil {
		s := fmt.Sprintf("Kubernetes version check skipped, with error getting kubectl version")
		continueWithError(err, sprintlnWarn(s))
		return nil
	}

	clientVerRe := regexp.MustCompile(`Client.*Major:"(\d+)".*Minor:"(\d+)"`)
	svrVerRe := regexp.MustCompile(`Server.*Major:"(\d+)".*Minor:"(\d+)"`)

	sub := clientVerRe.FindStringSubmatch(string(out))
	ver.Client = sub[1] + "." + sub[2]

	sub = svrVerRe.FindStringSubmatch(string(out))
	ver.Server = sub[1] + "." + sub[2]

	return ver
}

func multiWordReplace(s string, subname string, sub string) string {
	f := strings.Fields(sub)
	if len(f) > 1 {
		sub = "'" + sub + "'"
	}

	return strings.Replace(s, subname, sub, -1)
}

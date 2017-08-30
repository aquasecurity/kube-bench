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
	"github.com/spf13/viper"
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

var psFunc func(string) string
var statFunc func(string) (os.FileInfo, error)

func init() {
	psFunc = ps
	statFunc = os.Stat
}

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
		glog.V(2).Info(err)
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

// getBinaries finds which of the set of candidate executables are running
func getBinaries(v *viper.Viper, optional bool) map[string]string {
	binmap := make(map[string]string)

	for _, exeType := range v.AllKeys() {
		bin, err := findExecutable(v.GetStringSlice(exeType))
		if err != nil && !optional {
			exitWithError(fmt.Errorf("looking for %s executable but none of the candidates are running", exeType))
		}

		binmap[exeType] = bin
	}
	return binmap
}

// getConfigFiles finds which of the set of candidate config files exist
func getConfigFiles(v *viper.Viper) map[string]string {
	confmap := make(map[string]string)

	for _, confType := range v.AllKeys() {
		conf := findConfigFile(v.GetStringSlice(confType))
		if conf == "" {
			printlnWarn(fmt.Sprintf("Missing kubernetes config file for %s", confType))
		} else {
			confmap[confType] = conf
		}
	}

	return confmap
}

// verifyBin checks that the binary specified is running
func verifyBin(bin string) bool {

	// Strip any quotes
	bin = strings.Trim(bin, "'\"")

	// bin could consist of more than one word
	// We'll search for running processes with the first word, and then check the whole
	// proc as supplied is included in the results
	proc := strings.Fields(bin)[0]
	out := psFunc(proc)

	if !strings.Contains(out, bin) {
		return false
	}

	// Make sure we're not just matching on a partial word (e.g. if we're looking for apiserver, don't match on kube-apiserver)
	// This will give a false positive for matching "one two" against "zero one two-x" but it will do for now
	for _, f := range strings.Fields(out) {
		if f == proc {
			return true
		}
	}

	return false
}

// fundConfigFile looks through a list of possible config files and finds the first one that exists
func findConfigFile(candidates []string) string {
	for _, c := range candidates {
		_, err := statFunc(c)
		if err == nil {
			return c
		}
		if !os.IsNotExist(err) {
			exitWithError(fmt.Errorf("error looking for file %s: %v", c, err))
		}
	}

	return ""
}

// findExecutable looks through a list of possible executable names and finds the first one that's running
func findExecutable(candidates []string) (string, error) {
	for _, c := range candidates {
		if verifyBin(c) {
			return c, nil
		} else {
			glog.V(1).Info(fmt.Sprintf("executable '%s' not running", c))
		}
	}

	return "", fmt.Errorf("no candidates running")
}

func verifyKubeVersion(major string, minor string) {
	// These executables might not be on the user's path.

	_, err := exec.LookPath("kubectl")
	if err != nil {
		continueWithError(err, sprintlnWarn("Kubernetes version check skipped"))
		return
	}

	cmd := exec.Command("kubectl", "version")
	out, err := cmd.Output()
	if err != nil {
		s := fmt.Sprintf("Kubernetes version check skipped with error %v", err)
		continueWithError(err, sprintlnWarn(s))
		if len(out) == 0 {
			return
		}
	}

	msg := checkVersion("Client", string(out), major, minor)
	if msg != "" {
		continueWithError(fmt.Errorf(msg), msg)
	}

	msg = checkVersion("Server", string(out), major, minor)
	if msg != "" {
		continueWithError(fmt.Errorf(msg), msg)
	}
}

var regexVersionMajor = regexp.MustCompile("Major:\"([0-9]+)\"")
var regexVersionMinor = regexp.MustCompile("Minor:\"([0-9]+)\"")

func checkVersion(x string, s string, expMajor string, expMinor string) string {
	regexVersion, err := regexp.Compile(x + " Version: version.Info{(.*)}")
	if err != nil {
		return fmt.Sprintf("Error checking Kubernetes version: %v", err)
	}

	ss := regexVersion.FindString(s)
	major := versionMatch(regexVersionMajor, ss)
	minor := versionMatch(regexVersionMinor, ss)
	if major == "" || minor == "" {
		return fmt.Sprintf("Couldn't find %s version from kubectl output '%s'", x, s)
	}

	if major != expMajor || minor != expMinor {
		return fmt.Sprintf("Unexpected %s version %s.%s", x, major, minor)
	}

	return ""
}

func versionMatch(r *regexp.Regexp, s string) string {
	match := r.FindStringSubmatch(s)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func multiWordReplace(s string, subname string, sub string) string {
	f := strings.Fields(sub)
	if len(f) > 1 {
		sub = "'" + sub + "'"
	}

	return strings.Replace(s, subname, sub, -1)
}

func makeSubstitutions(s string, ext string, m map[string]string) string {
	for k, v := range m {
		subst := "$" + k + ext
		glog.V(1).Info(fmt.Sprintf("Substituting %s with '%s'\n", subst, v))
		s = multiWordReplace(s, subst, v)
	}

	return s
}

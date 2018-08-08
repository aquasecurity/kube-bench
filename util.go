package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/bench-common/check"
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
func getBinaries(v *viper.Viper) map[string]string {
	binmap := make(map[string]string)

	for _, component := range v.GetStringSlice("components") {
		s := v.Sub(component)
		if s == nil {
			continue
		}

		optional := s.GetBool("optional")
		bins := s.GetStringSlice("bins")
		if len(bins) > 0 {
			bin, err := findExecutable(bins)
			if err != nil && !optional {
				exitWithError(fmt.Errorf("need %s executable but none of the candidates are running", component))
			}

			// Default the executable name that we'll substitute to the name of the component
			if bin == "" {
				bin = component
				glog.V(2).Info(fmt.Sprintf("Component %s not running", component))
			} else {
				glog.V(2).Info(fmt.Sprintf("Component %s uses running binary %s", component, bin))
			}
			binmap[component] = bin
		}
	}

	return binmap
}

// getConfigFilePath locates the config files we should be using based on either the specified
// version, or the running version of kubernetes if not specified
func getConfigFilePath(specifiedVersion string, runningVersion string, filename string) (path string, err error) {
	var fileVersion string

	if specifiedVersion != "" {
		fileVersion = specifiedVersion
	} else {
		fileVersion = runningVersion
	}

	glog.V(2).Info(fmt.Sprintf("Looking for config for version %s", fileVersion))

	for {
		path = filepath.Join(cfgDir, fileVersion)
		file := filepath.Join(path, string(filename))
		glog.V(2).Info(fmt.Sprintf("Looking for config file: %s\n", file))

		if _, err = os.Stat(file); !os.IsNotExist(err) {
			if specifiedVersion == "" && fileVersion != runningVersion {
				glog.V(1).Info(fmt.Sprintf("No test file found for %s - using tests for Kubernetes %s\n", runningVersion, fileVersion))
			}
			return path, nil
		}

		// If we were given an explicit version to look for, don't look for any others
		if specifiedVersion != "" {
			return "", err
		}

		fileVersion = decrementVersion(fileVersion)
		if fileVersion == "" {
			return "", fmt.Errorf("no test files found <= runningVersion")
		}
	}
}

// decrementVersion decrements the version number
// We want to decrement individually even through versions where we don't supply test files
// just in case someone wants to specify their own test files for that version
func decrementVersion(version string) string {
	split := strings.Split(version, ".")
	minor, err := strconv.Atoi(split[1])
	if err != nil {
		return ""
	}
	if minor <= 1 {
		return ""
	}
	split[1] = strconv.Itoa(minor - 1)
	return strings.Join(split, ".")
}

// getConfigFiles finds which of the set of candidate config files exist
// accepts a string 't' which indicates the type of config file, conf,
// podspec or untifile.
func getConfigFiles(v *viper.Viper) map[string]string {
	confmap := make(map[string]string)

	for _, component := range v.GetStringSlice("components") {
		s := v.Sub(component)
		if s == nil {
			continue
		}

		// See if any of the candidate config files exist
		conf := findConfigFile(s.GetStringSlice("confs"))
		if conf == "" {
			if s.IsSet("defaultconf") {
				conf = s.GetString("defaultconf")
				glog.V(2).Info(fmt.Sprintf("Using default config file name '%s' for component %s", conf, component))
			} else {
				// Default the config file name that we'll substitute to the name of the component
				glog.V(2).Info(fmt.Sprintf("Missing config file for %s", component))
				conf = component
			}
		} else {
			glog.V(2).Info(fmt.Sprintf("Component %s uses config file '%s'", component, conf))
		}

		confmap[component] = conf
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

	// There could be multiple lines in the ps output
	// The binary needs to be the first word in the ps output, except that it could be preceded by a path
	// e.g. /usr/bin/kubelet is a match for kubelet
	// but apiserver is not a match for kube-apiserver
	reFirstWord := regexp.MustCompile(`^(\S*\/)*` + bin)
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if reFirstWord.Match([]byte(l)) {
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
		}
		glog.V(1).Info(fmt.Sprintf("executable '%s' not running", c))
	}

	return "", fmt.Errorf("no candidates running")
}

func multiWordReplace(s string, subname string, sub string) string {
	f := strings.Fields(sub)
	if len(f) > 1 {
		sub = "'" + sub + "'"
	}

	return strings.Replace(s, subname, sub, -1)
}

func getKubeVersion() (string, error) {
	// These executables might not be on the user's path.
	_, err := exec.LookPath("kubectl")

	if err != nil {
		_, err = exec.LookPath("kubelet")
		if err != nil {
			return "", fmt.Errorf("need kubectl or kubelet binaries to get kubernetes version")
		}
		return getKubeVersionFromKubelet(), nil
	}

	return getKubeVersionFromKubectl(), nil
}

func getKubeVersionFromKubectl() string {
	cmd := exec.Command("kubectl", "version", "--short")
	out, err := cmd.CombinedOutput()
	if err != nil {
		continueWithError(fmt.Errorf("%s", out), "")
	}

	return getVersionFromKubectlOutput(string(out))
}

func getKubeVersionFromKubelet() string {
	cmd := exec.Command("kubelet", "--version")
	out, err := cmd.CombinedOutput()

	if err != nil {
		continueWithError(fmt.Errorf("%s", out), "")
	}

	return getVersionFromKubeletOutput(string(out))
}

func getVersionFromKubectlOutput(s string) string {
	serverVersionRe := regexp.MustCompile(`Server Version: v(\d+.\d+)`)
	subs := serverVersionRe.FindStringSubmatch(s)
	if len(subs) < 2 {
		printlnWarn(fmt.Sprintf("Unable to get kubectl version, using default version: %s", defaultKubeVersion))
		return defaultKubeVersion
	}
	return subs[1]
}

func getVersionFromKubeletOutput(s string) string {
	serverVersionRe := regexp.MustCompile(`Kubernetes v(\d+.\d+)`)
	subs := serverVersionRe.FindStringSubmatch(s)
	if len(subs) < 2 {
		printlnWarn(fmt.Sprintf("Unable to get kubelet version, using default version: %s", defaultKubeVersion))
		return defaultKubeVersion
	}
	return subs[1]
}

func makeSubstitutions(s string, ext string, m map[string]string) string {
	for k, v := range m {
		subst := "$" + k + ext
		if v == "" {
			glog.V(2).Info(fmt.Sprintf("No subsitution for '%s'\n", subst))
			continue
		}
		glog.V(2).Info(fmt.Sprintf("Substituting %s with '%s'\n", subst, v))
		s = multiWordReplace(s, subst, v)
	}

	return s
}

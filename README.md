[![Build Status](https://travis-ci.org/aquasecurity/kube-bench.svg?branch=master)](https://travis-ci.org/aquasecurity/kube-bench)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker image](https://images.microbadger.com/badges/image/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench "Get your own image badge on microbadger.com")
[![Source commit](https://images.microbadger.com/badges/commit/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench)

# kube-bench

The Kubernetes Bench for Security is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes 1.6 Benchmark v1.0.0.

Tests are configured with YAML files, making this tool easy to update as test specifications evolve. 

![Kubernetes Bench for Security](https://raw.githubusercontent.com/aquasecurity/kube-bench/master/images/output.png "Kubernetes Bench for Security")


## Installation

You can either install kube-bench through a dedicated container, or compile it from source:

1. Container installation:
Run ```docker run --rm -v `pwd`:/host aquasec/kube-bench:latest```. This will copy the kube-bench binary and configuration to you host. You can then run ```./kube-bench <master|node>```.

2. Install from sources:
If Go is installed on the target machines, you can simply clone this repository and run as follows: 
```go get github.com/aquasecurity/kube-bench```
```cp $GOROOT/bin/kube-bench .```
```./kube-bench <master|node>```

## Usage
```./kube-bench [command]```

```
Available Commands:
  federated   Run benchmark checks for a Kubernetes federated deployment.
  help        Help about any command
  master      Run benchmark checks for a Kubernetes master node.
  node        Run benchmark checks for a Kubernetes node.

Flags:
  -c, --check string          A comma-delimited list of checks to run as specified in CIS document. Example --check="1.1.1,1.1.2"
      --config string         config file (default is ./cfg/config.yaml)
  -g, --group string          Run all the checks under this comma-delimited list of groups. Example --group="1.1"
      --installation string   Specify how kubernetes cluster was installed. Possible values are default,hyperkube,kops,kubeadm (default "default")
      --json                  Prints the results as JSON
  -v, --verbose               verbose output (default false)
```

## Configuration
Kubernetes config and binary file locations and names can vary from installation to installation, so these are configurable in the `cfg/config.yaml` file. 

They also tend to vary according to which tool was used to install Kubernetes. You can use the `--installation` flag to pick up a different default set of file names and locations. Again these defaults are configurable through `cfg/config.yaml` (and pull requests to correct or add default file locations are especially welcome). 

## Test config YAML representation
The tests are represented as YAML documents (installed by default into ./cfg).

An example is as listed below:
```
---
controls:
id: 1
text: "Master Checks"
type: "master"
groups:
- id: 1.1
  text: "Kube-apiserver"
  checks:
    - id: 1.1.1
      text: "Ensure that the --allow-privileged argument is set (Scored)"
      audit: "ps -ef | grep kube-apiserver | grep -v grep"
      tests:
      bin_op: or
      test_items:
      - flag: "--allow-privileged"
        set: true
      - flag: "--some-other-flag"
        set: false
      remediation: "Edit the /etc/kubernetes/config file on the master node and set the KUBE_ALLOW_PRIV parameter to '--allow-privileged=false'"
      scored: true
```

Recommendations (called `checks` in this document) can run on Kubernetes Master, Node or Federated API Servers.
Checks are organized into `groups` which share similar controls (things to check for) and are grouped together in the section of the CIS Kubernetes document.
These groups are further organized under `controls` which can be of the type `master`, `node` or `federated apiserver` to reflect the various Kubernetes node types.

## Tests
Tests are the items we actually look for to determine if a check is successful or not. Checks can have multiple tests, which must all be successful for the check to pass.

The syntax for tests:
```
tests:
- flag:
  set:
  compare:
    op:
    value:
...
```
Tests have various `operations` which are used to compare the output of audit commands for success.
These operations are:

- `eq`: tests if the flag value is equal to the compared value.
- `noteq`: tests if the flag value is unequal to the compared value.
- `gt`: tests if the flag value is greater than the compared value.
- `gte`: tests if the flag value is greater than or equal to the compared value.
- `lt`: tests if the flag value is less than the compared value.
- `lte`: tests if the flag value is less than or equal to the compared value.
- `has`: tests if the flag value contains the compared value.
- `nothave`: tests if the flag value does not contain the compared value.

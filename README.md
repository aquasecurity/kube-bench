[![Build Status](https://travis-ci.org/aquasecurity/kube-bench.svg?branch=master)](https://travis-ci.org/aquasecurity/kube-bench)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker image](https://images.microbadger.com/badges/image/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench "Get your own image badge on microbadger.com")
[![Source commit](https://images.microbadger.com/badges/commit/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench)

<img src="images/kube-bench.png" width="200" alt="kube-bench logo">

kube-bench is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/).

Tests are configured with YAML files, making this tool easy to update as test specifications evolve.

![Kubernetes Bench for Security](https://raw.githubusercontent.com/aquasecurity/kube-bench/master/images/output.png "Kubernetes Bench for Security")

## CIS Kubernetes Benchmark support

kube-bench supports the tests for multiple versions of Kubernetes (1.6, 1.7, 1.8, and 1.11) as defined in the CIS Benchmarks 1.0.0, 1.1.0, 1.2.0, and 1.3.0 respectively. It will determine the test set to run based on the Kubernetes version running on the machine.

## Installation

You can choose to
* run kube-bench from inside a container (sharing PID namespace with the host)
* run a container that installs kube-bench on the host, and then run kube-bench directly on the host
* install the latest binaries from the [Releases page](https://github.com/aquasecurity/kube-bench/releases),
* compile it from source.

### Running inside a container

You can avoid installing kube-bench on the host by running it inside a container using the host PID namespace and mounting the `/etc` and `/var` directories where the configuration and other files are located on the host, so that kube-bench can check their existence and permissions.

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t aquasec/kube-bench:latest <master|node>
```

You can even use your own configs by mounting them over the default ones in `/opt/kube-bench/cfg/`

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t -v path/to/my-config.yaml:/opt/kube-bench/cfg/config.yaml aquasec/kube-bench:latest <master|node>
```

> Note: the tests require either the kubelet or kubectl binary in the path in order to know the Kubernetes version. You can pass `-v $(which kubectl):/usr/bin/kubectl` to the above invocations to resolve this.

### Running in a kubernetes cluster

You can run kube-bench inside a pod, but it will need access to the host's PID namespace in order to check the running processes, as well as access to some directories on the host where config files and other files are stored. 

To run the tests on the master node, the pod needs to be scheduled on that node. This involves setting a nodeSelector and tolerations in the pod spec.

The supplied `job-node.yaml` and `job-master.yaml` files can be applied to run the tests as a job. For example:

```bash
$ kubectl apply -f job-master.yaml 
job.batch/kube-bench-master created

$ kubectl get pods
NAME                      READY   STATUS              RESTARTS   AGE
kube-bench-master-j76s9   0/1     ContainerCreating   0          3s

# Wait for a few seconds for the job to complete
$ kubectl get pods
NAME                      READY   STATUS      RESTARTS   AGE
kube-bench-master-j76s9   0/1     Completed   0          11s

# The results are held in the pod's logs
k logs kube-bench-master-j76s9
[INFO] 1 Master Node Security Configuration
[INFO] 1.1 API Server
...
```

The default labels applied to master nodes has changed since Kubernetes 1.11, so if you are using an older version you may need to modify the nodeSelector and tolerations to run the job on the master node.

### Installing from a container

This command copies the kube-bench binary and configuration files to your host from the Docker container:
** binaries compiled for linux-x86-64 only (so they won't run on OSX or Windows) **
```
docker run --rm -v `pwd`:/host aquasec/kube-bench:latest install
```

You can then run `./kube-bench <master|node>`.

### Installing from sources

If Go is installed on the target machines, you can simply clone this repository and run as follows (assuming your [$GOPATH is set](https://github.com/golang/go/wiki/GOPATH)):

```shell
go get github.com/aquasecurity/kube-bench
go get github.com/golang/dep/cmd/dep
cd $GOPATH/src/github.com/aquasecurity/kube-bench
$GOPATH/bin/dep ensure -vendor-only
go build -o kube-bench .

# See all supported options
./kube-bench --help

# Run the all checks on a master node
./kube-bench master

```

## Configuration

Kubernetes config and binary file locations and names can vary from installation to installation, so these are configurable in the `cfg/config.yaml` file.

For each type of node (*master*, *node* or *federated*) there is a list of components, and for each component there is a set of binaries (*bins*) and config files (*confs*) that kube-bench will look for (in the order they are listed). If your installation uses a different binary name or config file location for a Kubernetes component, you can add it to `cfg/config.yaml`.

* **bins** - If there is a *bins* list for a component, at least one of these binaries must be running. The tests will consider the parameters for the first binary in the list found to be running.
* **podspecs** - From version 1.2.0 of the benchmark (tests for Kubernetes 1.8), the remediation instructions were updated to assume that the configuration for several kubernetes components is defined in a pod YAML file, and podspec settings define where to look for that configuration.
* **confs** - If one of the listed config files is found, this will be considered for the test. Tests can continue even if no config file is found. If no file is found at any of the listed locations, and a *defaultconf* location is given for the component, the test will give remediation advice using the *defaultconf* location.
* **unitfiles** - From version 1.2.0 of the benchmark  (tests for Kubernetes 1.8), the remediation instructions were updated to assume that kubelet configuration is defined in a service file, and this setting defines where to look for that configuration.

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

# Roadmap
Going forward we plan to release updates to kube-bench to add support for new releases of the Benchmark, which in turn we can anticipate being made for each new Kubernetes release.

We welcome PRs and issue reports.

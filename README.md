[![Build Status](https://travis-ci.org/aquasecurity/kube-bench.svg?branch=master)](https://travis-ci.org/aquasecurity/kube-bench)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker image](https://images.microbadger.com/badges/image/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench "Get your own image badge on microbadger.com")
[![Source commit](https://images.microbadger.com/badges/commit/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench)
[![Coverage Status][cov-img]][cov]

[cov-img]: https://codecov.io/github/aquasecurity/kube-bench/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/kube-bench
<img src="images/kube-bench.png" width="200" alt="kube-bench logo">

kube-bench is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/). 

Note that it is impossible to inspect the master nodes of managed clusters, e.g. GKE, EKS and AKS, using kube-bench as one does not have access to such nodes, although it is still possible to use kube-bench to check worker node configuration in these environments.

Tests are configured with YAML files, making this tool easy to update as test specifications evolve.

![Kubernetes Bench for Security](https://raw.githubusercontent.com/aquasecurity/kube-bench/master/images/output.png "Kubernetes Bench for Security")

## CIS Kubernetes Benchmark support

kube-bench supports the tests for Kubernetes as defined in the CIS Benchmarks 1.0.0 to 1.4.0 respectively. 

| CIS Kubernetes Benchmark | kube-bench config | Kubernetes versions |
|---|---|---|
| 1.0.0| 1.6 | 1.6 |
| 1.1.0| 1.7 | 1.7 |
| 1.2.0| 1.8 | 1.8-1.10 |
| 1.3.0| 1.11 | 1.11-1.12 |
| 1.4.1| 1.13 | 1.13- |

By default kube-bench will determine the test set to run based on the Kubernetes version running on the machine.

There is also preliminary support for Red Hat's Openshift Hardening Guide for 3.10 and 3.11. Please note that kube-bench does not automatically detect Openshift - see below. 

## Installation

You can choose to
* run kube-bench from inside a container (sharing PID namespace with the host)
* run a container that installs kube-bench on the host, and then run kube-bench directly on the host
* install the latest binaries from the [Releases page](https://github.com/aquasecurity/kube-bench/releases),
* compile it from source.

## Running kube-bench

kube-bench automatically selects which `controls` to use based on the detected
node type and the version of kubernetes a cluster is running. This behaviour
can be overridden by specifying the `master` or `node` subcommand and the
`--version` flag on the command line. 

The kubernetes version can also be set with the KUBE_BENCH_VERSION environment variable.
The value of `--version` takes precedence over the value of KUBE_BENCH_VERSION.

For example:
run kube-bench against a master with version auto-detection:

```
kube-bench master
```

or run kube-bench against a node with the node `controls` for kubernetes 
version 1.13:
```
kube-bench node --version 1.13
```

`controls` for the various versions of kubernetes can be found in directories
with same name as the kubernetes versions under `cfg/`, for example `cfg/1.13`.
`controls` are also organized by distribution under the `cfg` directory for
example `cfg/ocp-3.10`.

### Running inside a container

You can avoid installing kube-bench on the host by running it inside a container using the host PID namespace and mounting the `/etc` and `/var` directories where the configuration and other files are located on the host, so that kube-bench can check their existence and permissions. 

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t aquasec/kube-bench:latest [master|node] --version 1.13
```

> Note: the tests require either the kubelet or kubectl binary in the path in order to auto-detect the Kubernetes version. You can pass `-v $(which kubectl):/usr/bin/kubectl` to resolve this. You will also need to pass in kubeconfig credentials. For example:

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -v $(which kubectl):/usr/bin/kubectl -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config -t aquasec/kube-bench:latest [master|node] 
```

You can use your own configs by mounting them over the default ones in `/opt/kube-bench/cfg/`

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t -v path/to/my-config.yaml:/opt/kube-bench/cfg/config.yam -v $(which kubectl):/usr/bin/kubectl -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config aquasec/kube-bench:latest [master|node]
```

### Running in a kubernetes cluster

You can run kube-bench inside a pod, but it will need access to the host's PID namespace in order to check the running processes, as well as access to some directories on the host where config files and other files are stored.

Master nodes are automatically detected by kube-bench and will run master checks when possible.
The detection is done by verifying that mandatory components for master, as defined in the config files, are running (see [Configuration](#configuration)).

The supplied `job.yaml` file can be applied to run the tests as a job. For example:

```bash
$ kubectl apply -f job.yaml
job.batch/kube-bench created

$ kubectl get pods
NAME                      READY   STATUS              RESTARTS   AGE
kube-bench-j76s9   0/1     ContainerCreating   0          3s

# Wait for a few seconds for the job to complete
$ kubectl get pods
NAME                      READY   STATUS      RESTARTS   AGE
kube-bench-j76s9   0/1     Completed   0          11s

# The results are held in the pod's logs
kubectl logs kube-bench-j76s9
[INFO] 1 Master Node Security Configuration
[INFO] 1.1 API Server
...
```

You can still force to run specific master or node checks using respectively `job-master.yaml` and `job-node.yaml`.

To run the tests on the master node, the pod needs to be scheduled on that node. This involves setting a nodeSelector and tolerations in the pod spec.

The default labels applied to master nodes has changed since Kubernetes 1.11, so if you are using an older version you may need to modify the nodeSelector and tolerations to run the job on the master node.

### Running in an EKS cluster

There is a `job-eks.yaml` file for running the kube-bench node checks on an EKS cluster. **Note that you must update the image reference in `job-eks.yaml`.** Typically you will push the container image for kube-bench to ECR and refer to it there in the YAML file.

There are two significant differences on EKS:

* It uses [config files in JSON format](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/)
* It's not possible to schedule jobs onto the master node, so master checks can't be performed

### Installing from a container

This command copies the kube-bench binary and configuration files to your host from the Docker container:
** binaries compiled for linux-x86-64 only (so they won't run on OSX or Windows) **
```
docker run --rm -v `pwd`:/host aquasec/kube-bench:latest install
```

You can then run `./kube-bench [master|node]`.

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

# Run the all checks
./kube-bench

```
## Running on OpenShift 

kube-bench includes a set of test files for Red Hat's OpenShift hardening guide for OCP 3.10 and 3.11. To run this you will need to specify `--version ocp-3.10` when you run the `kube-bench` command (either directly or through YAML). This config version is valid for OCP 3.10 and 3.11. 

## Output

There are three output states
- [PASS] and [FAIL] indicate that a test was run successfully, and it either passed or failed
- [WARN] means this test needs further attention, for example it is a test that needs to be run manually 
- [INFO] is informational output that needs no further action.

## Configuration

Kubernetes config and binary file locations and names can vary from installation to installation, so these are configurable in the `cfg/config.yaml` file.

Any settings in the version-specific config file `cfg/<version>/config.yaml` take precedence over settings in the main `cfg/config.yaml` file.

You can read more about `kube-bench` configuration in our [documentation](docs/README.md#configuration-and-variables).

## Test config YAML representation

The tests (or "controls") are represented as YAML documents (installed by default into ./cfg). There are different versions of these test YAML files reflecting different versions of the CIS Kubernetes Benchmark. You will find more information about the test file YAML definitions in our [documentation](docs/README.md).

### Omitting checks

If you decide that a recommendation is not appropriate for your environment, you can choose to omit it by editing the test YAML file to give it the check type `skip` as in this example: 

```yaml
  checks:
  - id: 2.1.1
    text: "Ensure that the --allow-privileged argument is set to false (Scored)"
    type: "skip"
    scored: true
```

No tests will be run for this check and the output will be marked [INFO].

# Roadmap
Going forward we plan to release updates to kube-bench to add support for new releases of the Benchmark, which in turn we can anticipate being made for each new Kubernetes release.

We welcome PRs and issue reports.

# Testing locally with kind

Our makefile contains targets to test your current version of kube-bench inside a [Kind](https://kind.sigs.k8s.io/) cluster. This can be very handy if you don't want to run a real kubernetes cluster for development purpose.

First you'll need to create the cluster using `make kind-test-cluster` this will create a new cluster if it cannot be found on your machine. By default the cluster is named `kube-bench` but you can change the name by using the environment variable `KIND_PROFILE`.

*If kind cannot be found on your system the target will try to install it using `go get`*

Next you'll have to build the kube-bench docker image using `make build-docker`, then we will be able to push the docker image to the cluster using `make kind-push`.

Finally we can use the `make kind-run` target to run the current version of kube-bench in the cluster and follow the logs of pods created. (Ctrl+C to exit)

Everytime you want to test a change, you'll need to rebuild the docker image and push it to cluster before running it again. ( `make build-docker kind-push kind-run` )

# GitHub Issues

## Bugs

If you think you have found a bug please follow the instructions below.

- Please spend a small amount of time giving due diligence to the issue tracker. Your issue might be a duplicate.
- Open a [new issue](https://github.com/aquasecurity/kube-bench/issues/new) if a duplicate doesn't already exist.
- Note the version of kube-bench you are running (from `kube-bench version`) and the command line options you are using.
- Note the version of kubernetes you are running (from `kubectl version` or `oc version` for Openshift).
- Set `-v 10` command line option and save the log output. Please paste this into your issue.
- Remember users might be searching for your issue in the future, so please give it a meaningful title to help others.

## Features

We also use the GitHub issue tracker to track feature requests. If you have an idea to make kube-bench even more awesome follow the steps below.

- Open a [new issue](https://github.com/aquasecurity/kube-bench/issues/new).
- Remember users might be searching for your issue in the future, so please give it a meaningful title to helps others.
- Clearly define the use case, using concrete examples. For example: I type `this` and kube-bench does `that`.
- If you would like to include a technical design for your feature please feel free to do so.

## Pull Requests 

We welcome pull requests! 

- Your PR is more likely to be accepted if it focuses on just one change.
- Please include a comment with the results before and after your change. 
- Your PR is more likely to be accepted if it includes tests. (We have not historically been very strict about tests, but we would like to improve this!). 
- You're welcome to submit a draft PR if you would like early feedback on an idea or an approach. 
- Happy coding!


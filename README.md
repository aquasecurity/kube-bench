[![GitHub Release][release-img]][release]
![Downloads][download]
![Docker Pulls][docker-pull]
[![Go Report Card][report-card-img]][report-card]
[![Build Status](https://github.com/aquasecurity/kube-bench/workflows/Build/badge.svg?branch=main)](https://github.com/aquasecurity/kube-bench/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/aquasecurity/kube-bench/blob/main/LICENSE)
[![Docker image](https://images.microbadger.com/badges/image/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench "Get your own image badge on microbadger.com")
[![Source commit](https://images.microbadger.com/badges/commit/aquasec/kube-bench.svg)](https://microbadger.com/images/aquasec/kube-bench)
[![Coverage Status][cov-img]][cov]

[download]: https://img.shields.io/github/downloads/aquasecurity/kube-bench/total?logo=github
[release-img]: https://img.shields.io/github/release/aquasecurity/kube-bench.svg?logo=github
[release]: https://github.com/aquasecurity/kube-bench/releases
[docker-pull]: https://img.shields.io/docker/pulls/aquasec/kube-bench?logo=docker&label=docker%20pulls%20%2F%20kube-bench
[cov-img]: https://codecov.io/github/aquasecurity/kube-bench/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/kube-bench
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/kube-bench
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/kube-bench

<img src="images/kube-bench.png" width="200" alt="kube-bench logo">

kube-bench is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/).

Tests are configured with YAML files, making this tool easy to update as test specifications evolve.

### Please Note

1. kube-bench implements the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/) as closely as possible. Please raise issues here if kube-bench is not correctly implementing the test as described in the Benchmark. To report issues in the Benchmark itself (for example, tests that you believe are inappropriate), please join the [CIS community](https://cisecurity.org).

1. There is not a one-to-one mapping between releases of Kubernetes and releases of the CIS benchmark. See [CIS Kubernetes Benchmark support](docs/Platforms#cis-kubernetes-benchmark-support) to see which releases of Kubernetes are covered by different releases of the benchmark.

1. It is impossible to inspect the master nodes of managed clusters, e.g. GKE, EKS, AKS and ACK, using kube-bench as one does not have access to such nodes, although it is still possible to use kube-bench to check worker node configuration in these environments.


![Kubernetes Bench for Security](https://raw.githubusercontent.com/aquasecurity/kube-bench/main/docs/images/output.png "Kubernetes Bench for Security")


By default, kube-bench will determine the test set to run based on the Kubernetes version running on the machine.
- see the section below on [Running kube-bench](https://github.com/aquasecurity/kube-bench#running-kube-bench).



## Contributing
Kindly read [Contributing.md](docs/Contributing.md) before contributing. 
We welcome PRs and issue reports.

## Roadmap

Going forward we plan to release updates to kube-bench to add support for new releases of the CIS Benchmark. Note that these are not released as frequently as Kubernetes releases.


[download]: https://img.shields.io/github/downloads/aquasecurity/kube-bench/total?logo=github
[release-img]: https://img.shields.io/github/release/aquasecurity/kube-bench.svg?logo=github
[release]: https://github.com/aquasecurity/kube-bench/releases
[docker-pull]: https://img.shields.io/docker/pulls/aquasec/kube-bench?logo=docker&label=docker%20pulls%20%2F%20kube-bench
[docker]: https://hub.docker.com/r/aquasec/kube-bench
[cov-img]: https://codecov.io/github/aquasecurity/kube-bench/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/kube-bench
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/kube-bench
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/kube-bench

![Kube-bench Logo](images/kube-bench.jpg)
[![GitHub Release][release-img]][release]
[![Downloads][download]][release]
[![Docker Pulls][docker-pull]][docker]
[![Go Report Card][report-card-img]][report-card]
[![Build Status](https://github.com/aquasecurity/kube-bench/workflows/Build/badge.svg?branch=main)](https://github.com/aquasecurity/kube-bench/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/aquasecurity/kube-bench/blob/main/LICENSE)
[![Coverage Status][cov-img]][cov]


# Kube-bench 

kube-bench is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/).

Tests are configured with YAML files, making this tool easy to update as test specifications evolve.


1. kube-bench implements the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/) as closely as possible. Please raise issues here if kube-bench is not correctly implementing the test as described in the Benchmark. To report issues in the Benchmark itself (for example, tests that you believe are inappropriate), please join the [CIS community](https://cisecurity.org).

1. There is not a one-to-one mapping between releases of Kubernetes and releases of the CIS benchmark. See [CIS Kubernetes Benchmark support](#cis-kubernetes-benchmark-support) to see which releases of Kubernetes are covered by different releases of the benchmark.

1. It is impossible to inspect the master nodes of managed clusters, e.g. GKE, EKS, AKS and ACK, using kube-bench as one does not have access to such nodes, although it is still possible to use kube-bench to check worker node configuration in these environments.

For help and more information go to our [github discussions q&a](https://github.com/aquasecurity/kube-bench/discussions/categories/q-a)

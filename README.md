# kubernetes-bench-security

The Kubernetes Bench for Security is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes 1.6 Benchmark v1.0.0.

Tests are configured with YAML files, making this tool easy to update as test specifications evolve. 

## Installation

Install by cloning this repository and running 

```make install```

This builds the application and also copies the test configuration files into a .cis_kubernetes directory in your home directory. 

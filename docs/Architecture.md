## Test config YAML representation

The tests (or "controls") are represented as YAML documents (installed by default into `./cfg`). There are different versions of these test YAML files reflecting different [versions and platforms of the CIS Kubernetes Benchmark](./Platforms.md). You will find more information about the test file YAML definitions in our [controls documentation](./Controls.md).

## Kube-bench benchmarks

The test files for the various versions of CIS Benchmark can be found in directories
with same name as the CIS Benchmark versions under `cfg/`, for example `cfg/cis-1.5`.

Check the contents of the benchmark directory under `cfg` to see which targets are available for that benchmark. Each file except `config.yaml` represents a target (also known as a `control` in other parts of this documentation). 

The following table shows the valid targets based on the CIS Benchmark version.
| CIS Benchmark | Targets |
|---|---|
| cis-1.5| master, controlplane, node, etcd, policies |
| cis-1.6| master, controlplane, node, etcd, policies |
| gke-1.0| master, controlplane, node, etcd, policies, managedservices |
| eks-1.0| controlplane, node, policies, managedservices |
| ack-1.0| master, controlplane, node, etcd, policies, managedservices |
| rh-0.7| master,node|
| rh-1.0| master, controlplane, node, etcd, policies |





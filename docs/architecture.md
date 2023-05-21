## Test config YAML representation

The tests (or "controls") are maintained in YAML documents. There are different versions of these test YAML files reflecting different [versions and platforms of the CIS Kubernetes Benchmark](./platforms.md). You will find more information about the test file YAML definitions in our [controls documentation](./controls.md).

## Kube-bench benchmarks

The test files for the various versions of Benchmarks can be found in directories
with same name as the Benchmark versions under the `cfg` directory next to the kube-bench executable, 
for example `./cfg/cis-1.5` will contain all test files for [CIS Kubernetes Benchmark v1.5.1](https://workbench.cisecurity.org/benchmarks/4892) which are:
master.yaml, controlplane.yaml, node.yaml, etcd.yaml, policies.yaml and config.yaml 

Check the contents of the benchmark directory under `cfg` to see which targets are available for that benchmark. Each file except `config.yaml` represents a target (also known as a `control` in other parts of this documentation). 

The following table shows the valid targets based on the CIS Benchmark version.

| CIS Benchmark | Targets |
|---------------|---------|
| cis-1.5       | master, controlplane, node, etcd, policies |
| cis-1.6       | master, controlplane, node, etcd, policies |
| cis-1.20      | master, controlplane, node, etcd, policies |
| cis-1.23      | master, controlplane, node, etcd, policies |
| cis-1.24      | master, controlplane, node, etcd, policies |
| cis-1.7       | master, controlplane, node, etcd, policies |
| gke-1.0       | master, controlplane, node, etcd, policies, managedservices |
| gke-1.2.0     | controlplane, node, policies, managedservices |
| eks-1.0.1     | controlplane, node, policies, managedservices |
| eks-1.1.0     | controlplane, node, policies, managedservices |
| eks-1.2.0     | controlplane, node, policies, managedservices |
| ack-1.0       | master, controlplane, node, etcd, policies, managedservices |
| aks-1.0       | controlplane, node, policies, managedservices |
| rh-0.7        | master,node|
| rh-1.0        | master, controlplane, node, etcd, policies |
| cis-1.6-k3s   | master, controlplane, node, etcd, policies |

The following table shows the valid DISA STIG versions

| STIG                       | Targets |
|----------------------------|---------|
| eks-stig-kubernetes-v1r6   | master, controlplane, node, policies, managedservices |



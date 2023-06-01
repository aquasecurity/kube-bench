
## CIS Kubernetes Benchmark support

kube-bench supports running tests for Kubernetes.
Most of our supported benchmarks are defined in one of the following:
    [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes/)
    [STIG Document Library](https://public.cyber.mil/stigs/downloads)
    
Some defined by other hardenening guides.

| Source | Kubernetes Benchmark                                                                                        | kube-bench config        | Kubernetes versions |
|------|-------------------------------------------------------------------------------------------------------------|--------------------------|---------------------|
| CIS  | [1.5.1](https://workbench.cisecurity.org/benchmarks/4892)                                                   | cis-1.5                  | 1.15                |
| CIS  | [1.6.0](https://workbench.cisecurity.org/benchmarks/4834)                                                   | cis-1.6                  | 1.16-1.18           |
| CIS  | [1.20](https://workbench.cisecurity.org/benchmarks/6246)                                                    | cis-1.20                 | 1.19-1.21           |
| CIS  | [1.23](https://workbench.cisecurity.org/benchmarks/7532)                                                    | cis-1.23                 | 1.22-1.23           |
| CIS  | [1.24](https://workbench.cisecurity.org/benchmarks/10873)                                                   | cis-1.24                 | 1.24                |
| CIS  | [1.7](https://workbench.cisecurity.org/benchmarks/11107)                                                    | cis-1.7                  | 1.25                |
| CIS  | [GKE 1.0.0](https://workbench.cisecurity.org/benchmarks/4536)                                               | gke-1.0                  | GKE                 |
| CIS  | [GKE 1.2.0](https://workbench.cisecurity.org/benchmarks/7534)                                               | gke-1.2.0                | GKE                 |
| CIS  | [EKS 1.0.1](https://workbench.cisecurity.org/benchmarks/6041)                                               | eks-1.0.1                | EKS                 |
| CIS  | [EKS 1.1.0](https://workbench.cisecurity.org/benchmarks/6248)                                               | eks-1.1.0                | EKS                 |
| CIS  | [EKS 1.2.0](https://workbench.cisecurity.org/benchmarks/9681)                                               | eks-1.2.0                | EKS                 |
| CIS  | [ACK 1.0.0](https://workbench.cisecurity.org/benchmarks/6467)                                               | ack-1.0                  | ACK                 |
| CIS  | [AKS 1.0.0](https://workbench.cisecurity.org/benchmarks/6347)                                               | aks-1.0                  | AKS                 |
| RHEL | RedHat OpenShift hardening guide                                                                            | rh-0.7                   | OCP 3.10-3.11       |
| CIS  | [OCP4 1.1.0](https://workbench.cisecurity.org/benchmarks/6778)                                              | rh-1.0                   | OCP 4.1-            |
| CIS  | [1.6.0-k3s](https://docs.rancher.cn/docs/k3s/security/self-assessment/_index)                               | cis-1.6-k3s              | k3s v1.16-v1.24     |
| DISA | [Kubernetes Ver 1, Rel 6](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V1R6_STIG.zip) | eks-stig-kubernetes-v1r6 | EKS                 |
| CIS  | [TKGI 1.2.53](https://network.pivotal.io/products/p-compliance-scanner#/releases/1248397)                   | tkgi-1.2.53              | vmware              |

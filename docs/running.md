
## Running kube-bench

If you run kube-bench directly from the command line you may need to be root / sudo to have access to all the config files.

By default kube-bench attempts to auto-detect the running version of Kubernetes, and map this to the corresponding CIS Benchmark version. For example, Kubernetes version 1.15 is mapped to CIS Benchmark version `cis-1.15` which is the benchmark version valid for Kubernetes 1.15.

kube-bench also attempts to identify the components running on the node, and uses this to determine which tests to run (for example, only running the master node tests if the node is running an API server). 

**Please note**
It is impossible to inspect the master nodes of managed clusters, e.g. GKE, EKS, AKS and ACK, using kube-bench as one does not have access to such nodes, although it is still possible to use kube-bench to check worker node configuration in these environments.

### Running inside a container

You can avoid installing kube-bench on the host by running it inside a container using the host PID namespace and mounting the `/etc` and `/var` directories where the configuration and other files are located on the host so that kube-bench can check their existence and permissions.

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t docker.io/aquasec/kube-bench:latest --version 1.18
```

> Note: the tests require either the kubelet or kubectl binary in the path in order to auto-detect the Kubernetes version. You can pass `-v $(which kubectl):/usr/local/mount-from-host/bin/kubectl` to resolve this. You will also need to pass in kubeconfig credentials. For example:

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -v $(which kubectl):/usr/local/mount-from-host/bin/kubectl -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config -t docker.io/aquasec/kube-bench:latest 
```

You can use your own configs by mounting them over the default ones in `/opt/kube-bench/cfg/`

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t -v path/to/my-config.yaml:/opt/kube-bench/cfg/config.yaml -v $(which kubectl):/usr/local/mount-from-host/bin/kubectl -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config docker.io/aquasec/kube-bench:latest
```

### Running in a Kubernetes cluster

You can run kube-bench inside a pod, but it will need access to the host's PID namespace in order to check the running processes, as well as access to some directories on the host where config files and other files are stored.

The `job.yaml` file (available in the root directory of the repository) can be applied to run the tests as a Kubernetes `Job`. For example:

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

To run tests on the master node, the pod needs to be scheduled on that node. This involves setting a nodeSelector and tolerations in the pod spec.

The default labels applied to master nodes has changed since Kubernetes 1.11, so if you are using an older version you may need to modify the nodeSelector and tolerations to run the job on the master node.
### Running in an AKS cluster

1. Create an AKS cluster(e.g. 1.13.7) with RBAC enabled, otherwise there would be 4 failures

1. Use the [kubectl-enter plugin](https://github.com/kvaps/kubectl-enter) to shell into a node
`
kubectl-enter {node-name}
`
or ssh to one agent node
could open nsg 22 port and assign a public ip for one agent node (only for testing purpose)

1. Run CIS benchmark to view results:
```
docker run --rm -v `pwd`:/host docker.io/aquasec/kube-bench:latest install
./kube-bench 
```
kube-bench cannot be run on AKS master nodes

### Running CIS benchmark in an EKS cluster

There is a `job-eks.yaml` file for running the kube-bench node checks on an EKS cluster. The significant difference on EKS is that it's not possible to schedule jobs onto the master node, so master checks can't be performed

1. To create an EKS Cluster refer to [Getting Started with Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html) in the *Amazon EKS User Guide*
  - Information on configuring `eksctl`, `kubectl` and the AWS CLI is within
2. Create an [Amazon Elastic Container Registry (ECR)](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html) repository to host the kube-bench container image
```
aws ecr create-repository --repository-name k8s/kube-bench --image-tag-mutability MUTABLE
```
3. Download, build and push the kube-bench container image to your ECR repo
```
git clone https://github.com/aquasecurity/kube-bench.git
cd kube-bench
aws ecr get-login-password --region <AWS_REGION> | docker login --username AWS --password-stdin <AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com
docker build -t k8s/kube-bench .
docker tag k8s/kube-bench:latest <AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com/k8s/kube-bench:latest
docker push <AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com/k8s/kube-bench:latest
```
4. Copy the URI of your pushed image, the URI format is like this: `<AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com/k8s/kube-bench:latest`
5. Replace the `image` value in `job-eks.yaml` with the URI from Step 4
6. Run the kube-bench job on a Pod in your Cluster: `kubectl apply -f job-eks.yaml`
7. Find the Pod that was created, it *should* be in the `default` namespace: `kubectl get pods --all-namespaces`
8. Retrieve the value of this Pod and output the report, note the Pod name will vary: `kubectl logs kube-bench-<value>`
  - You can save the report for later reference: `kubectl logs kube-bench-<value> > kube-bench-report.txt`

### Running DISA STIG in an EKS cluster

There is a `job-eks-stig.yaml` file for running the kube-bench node checks on an EKS cluster. The significant difference on EKS is that it's not possible to schedule jobs onto the master node, so master checks can't be performed

1. To create an EKS Cluster refer to [Getting Started with Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html) in the *Amazon EKS User Guide*
  - Information on configuring `eksctl`, `kubectl` and the AWS CLI is within
2. Create an [Amazon Elastic Container Registry (ECR)](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html) repository to host the kube-bench container image
```
aws ecr create-repository --repository-name k8s/kube-bench --image-tag-mutability MUTABLE
```
3. Download, build and push the kube-bench container image to your ECR repo
```
git clone https://github.com/aquasecurity/kube-bench.git
cd kube-bench
aws ecr get-login-password --region <AWS_REGION> | docker login --username AWS --password-stdin <AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com
docker build -t k8s/kube-bench .
docker tag k8s/kube-bench:latest <AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com/k8s/kube-bench:latest
docker push <AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com/k8s/kube-bench:latest
```
4. Copy the URI of your pushed image, the URI format is like this: `<AWS_ACCT_NUMBER>.dkr.ecr.<AWS_REGION>.amazonaws.com/k8s/kube-bench:latest`
5. Replace the `image` value in `job-eks-stig.yaml` with the URI from Step 4
6. Run the kube-bench job on a Pod in your Cluster: `kubectl apply -f job-eks-stig.yaml`
7. Find the Pod that was created, it *should* be in the `default` namespace: `kubectl get pods --all-namespaces`
8. Retrieve the value of this Pod and output the report, note the Pod name will vary: `kubectl logs kube-bench-<value>`
  - You can save the report for later reference: `kubectl logs kube-bench-<value> > kube-bench-report.txt`

### Running on OpenShift

| OpenShift Hardening Guide | kube-bench config |
| ------------------------- | ----------------- |
| ocp-3.10 +                | rh-0.7            |
| ocp-4.1 +                 | rh-1.0            |

kube-bench includes a set of test files for Red Hat's OpenShift hardening guide for OCP 3.10 and 4.1. To run this you will need to specify `--benchmark rh-07`, or `--version ocp-3.10` or,`--version ocp-4.5` or `--benchmark rh-1.0` 

`kube-bench` supports auto-detection, when you run the `kube-bench` command it will autodetect if running in openshift environment.

Since running `kube-bench` requires elevated privileges, the `privileged` SecurityContextConstraint needs to be applied to the ServiceAccount used for the `Job`:

```
oc create namespace kube-bench
oc adm policy add-scc-to-user privileged --serviceaccount default
oc apply -f job.yaml
```

### Running in a GKE cluster

| CIS Benchmark | Targets                                                     |
| ------------- | ----------------------------------------------------------- |
| gke-1.0       | master, controlplane, node, etcd, policies, managedservices |
| gke-1.2.0     | master, controlplane, node, policies, managedservices       |

kube-bench includes benchmarks for GKE. To run this you will need to specify `--benchmark gke-1.0` or `--benchmark gke-1.2.0` when you run the `kube-bench` command.

To run the benchmark as a job in your GKE cluster apply the included `job-gke.yaml`.

```
kubectl apply -f job-gke.yaml
```

### Running in a ACK cluster

| CIS Benchmark | Targets                                                     |
| ------------- | ----------------------------------------------------------- |
| ack-1.0       | master, controlplane, node, etcd, policies, managedservices |

kube-bench includes benchmarks for Alibaba Cloud Container Service For Kubernetes (ACK).
To run this you will need to specify `--benchmark ack-1.0` when you run the `kube-bench` command.

To run the benchmark as a job in your ACK cluster apply the included `job-ack.yaml`.

```
kubectl apply -f job-ack.yaml
```

### Running in a VMware TKGI cluster

| CIS Benchmark | Targets                                    |
|---------------|--------------------------------------------|
| tkgi-1.2.53   | master, etcd, controlplane, node, policies |

kube-bench includes benchmarks for VMware tkgi platform.
To run this you will need to specify `--benchmark tkgi-1.2.53` when you run the `kube-bench` command.

To run the benchmark as a job in your VMware tkgi cluster apply the included `job-tkgi.yaml`.

```
kubectl apply -f job-tkgi.yaml
```
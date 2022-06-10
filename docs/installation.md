## Installation

You can choose to
* Run kube-bench from inside a container (sharing PID namespace with the host). See [Running inside a container](./running.md#running-inside-a-container) for additional details.
* Run a container that installs kube-bench on the host, and then run kube-bench directly on the host. See [Installing from a container](#installing-from-a-container) for additional details.
* install the latest binaries from the [Releases page](https://github.com/aquasecurity/kube-bench/releases), though please note that you also need to download the config and test files from the `cfg` directory. See [Download and Install binaries](#download-and-install-binaries) for details.
* Compile it from source. See [Installing from sources](#installing-from-sources) for details.


### Download and Install binaries

It is possible to manually install and run kube-bench release binaries. In order to do that, you must have access to your Kubernetes cluster nodes. Note that if you're using one of the managed Kubernetes services (e.g. EKS, AKS, GKE, ACK, OCP), you will not have access to the master nodes of your cluster and you can’t perform any tests on the master nodes.

First, log into one of the nodes using SSH.

Install kube-bench binary for your platform using the commands below. Note that there may be newer releases available. See [releases page](https://github.com/aquasecurity/kube-bench/releases).

Ubuntu/Debian:

```
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.2/kube-bench_0.6.2_linux_amd64.deb -o kube-bench_0.6.2_linux_amd64.deb

sudo apt install ./kube-bench_0.6.2_linux_amd64.deb -f
```

RHEL:

```
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.2/kube-bench_0.6.2_linux_amd64.rpm -o kube-bench_0.6.2_linux_amd64.rpm

sudo yum install kube-bench_0.6.2_linux_amd64.rpm -y
```

Alternatively, you can manually download and extract the kube-bench binary:

```
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.2/kube-bench_0.6.2_linux_amd64.tar.gz -o kube-bench_0.6.2_linux_amd64.tar.gz

tar -xvf kube-bench_0.6.2_linux_amd64.tar.gz
```

You can then run kube-bench directly:
```
kube-bench
```

If you manually downloaded the kube-bench binary (using curl command above), you have to specify the location of configuration directory and file. For example:
```
./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml 
```

See previous section on [Running kube-bench](./running.md#running-kube-bench) for further details on using the kube-bench binary.

### Installing from sources

If Go is installed on the target machines, you can simply clone this repository and run as follows (assuming your [`GOPATH` is set](https://github.com/golang/go/wiki/GOPATH)) as per this example:

```shell
# Create a target directory for the clone, inside the $GOPATH
mkdir -p $GOPATH/src/github.com/aquasecurity/kube-bench

# Clone this repository, using SSH
git clone git@github.com:aquasecurity/kube-bench.git $GOPATH/src/github.com/aquasecurity/kube-bench

# Install the pre-requisites
go get github.com/aquasecurity/kube-bench

# Change to the kube-bench directory
cd $GOPATH/src/github.com/aquasecurity/kube-bench

# Build the kube-bench binary
go build -o kube-bench .

# See all supported options
./kube-bench --help

# Run all checks
./kube-bench
```


### Installing from a container

This command copies the kube-bench binary and configuration files to your host from the Docker container:
**binaries compiled for linux-x86-64 only (so they won't run on macOS or Windows)**
```
docker run --rm -v `pwd`:/host docker.io/aquasec/kube-bench:latest install
```

You can then run `./kube-bench`.

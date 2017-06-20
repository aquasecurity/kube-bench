FROM golang:1.8
WORKDIR /kube-bench
RUN go get github.com/aquasecurity/kube-bench
RUN cp /go/bin/kube-bench /kube-bench/ && chmod +x /kube-bench/kube-bench
WORKDIR /kube-bench/cfg
RUN wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/config.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/federated.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/master.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/node.yaml
# When Docker Hub supports it, we would split this into a multi-stage build with the second part based on, say, alpine for size
WORKDIR /
ADD entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh

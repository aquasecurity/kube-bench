FROM golang:1.4.1
RUN mkdir /kube-bench
WORKDIR /kube-bench
RUN wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/config.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/federated.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/master.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kube-bench/master/cfg/node.yaml
RUN go get github.com/aquasecurity/kube-bench
RUN cp /go/bin/kubernetes-bench /kube-bench/ && chmod +x /kube-bench/kube-bench

FROM alpine:latest
RUN mkdir -p /kube-bench/cfg
COPY --from=0 /kube-bench/kube-bench /kube-bench/kube-bench
COPY --from=0 /kube-bench/config.yaml /kube-bench/cfg/config.yaml
COPY --from=0 /kube-bench/federated.yaml /kube-bench/cfg/federated.yaml
COPY --from=0 /kube-bench/master.yaml /kube-bench/cfg/master.yaml
COPY --from=0 /kube-bench/node.yaml /kube-bench/cfg/node.yaml
ADD entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh

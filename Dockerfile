FROM golang:1.4.1
RUN mkdir /kube-bench
WORKDIR /kube-bench
RUN wget https://raw.githubusercontent.com/aquasecurity/kubernetes-bench-security/master/cfg/config.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kubernetes-bench-security/master/cfg/federated.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kubernetes-bench-security/master/cfg/master.yaml && \
    wget https://raw.githubusercontent.com/aquasecurity/kubernetes-bench-security/master/cfg/node.yaml
RUN go get github.com/aquasecurity/kubernetes-bench-security
RUN cp /go/bin/kubernetes-bench-security /kube-bench/ && chmod +x /kube-bench/kubernetes-bench-security

FROM alpine:latest
RUN mkdir -p /kube-bench/cfg
COPY --from=0 /kube-bench/kubernetes-bench-security /kube-bench/kube-bench
COPY --from=0 /kube-bench/config.yaml /kube-bench/cfg/config.yaml
COPY --from=0 /kube-bench/federated.yaml /kube-bench/cfg/federated.yaml
COPY --from=0 /kube-bench/master.yaml /kube-bench/cfg/master.yaml
COPY --from=0 /kube-bench/node.yaml /kube-bench/cfg/node.yaml
ADD entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh

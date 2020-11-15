FROM golang:1.15 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
COPY go.mod go.sum ./
COPY main.go .
COPY check/ check/
COPY cmd/ cmd/
COPY internal/ internal/
ARG KUBEBENCH_VERSION
ARG GOOS=linux
ARG GOARCH=amd64
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -a -ldflags "-X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=${KUBEBENCH_VERSION} -w" -o /go/bin/kube-bench

FROM alpine:3.12 AS run
WORKDIR /opt/kube-bench/
# add GNU ps for -C, -o cmd, and --no-headers support
# https://github.com/aquasecurity/kube-bench/issues/109
RUN apk --no-cache add procps

# Openssl is used by OpenShift tests
# https://github.com/aquasecurity/kube-bench/issues/535
RUN apk --no-cache add openssl

ENV PATH=$PATH:/usr/local/mount-from-host/bin

COPY --from=build /go/bin/kube-bench /usr/local/bin/kube-bench
COPY entrypoint.sh .
COPY cfg/ cfg/
ENTRYPOINT ["./entrypoint.sh"]
CMD ["install"]

# Build-time metadata as defined at http://label-schema.org
ARG BUILD_DATE
ARG VCS_REF
LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="kube-bench" \
    org.label-schema.description="Run the CIS Kubernetes Benchmark tests" \
    org.label-schema.url="https://github.com/aquasecurity/kube-bench" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/aquasecurity/kube-bench" \
    org.label-schema.schema-version="1.0"

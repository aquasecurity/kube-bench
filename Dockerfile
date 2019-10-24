FROM golang:1.12 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
ADD go.mod go.sum ./
ADD main.go .
ADD check/ check/
ADD cmd/ cmd/
ARG KUBEBENCH_VERSION
RUN GO111MODULE=on CGO_ENABLED=0 go install -a -ldflags "-X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=${KUBEBENCH_VERSION} -w"

FROM alpine:3.10 AS run
WORKDIR /opt/kube-bench/
# add GNU ps for -C, -o cmd, and --no-headers support
# https://github.com/aquasecurity/kube-bench/issues/109
RUN apk --no-cache add procps
COPY --from=build /go/bin/kube-bench /usr/local/bin/kube-bench
ADD entrypoint.sh .
ADD cfg/ cfg/
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

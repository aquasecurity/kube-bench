FROM golang:1.20.4 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
COPY makefile makefile
COPY go.mod go.sum ./
COPY main.go .
COPY check/ check/
COPY cmd/ cmd/
COPY internal/ internal/
ARG KUBEBENCH_VERSION
RUN make build && cp kube-bench /go/bin/kube-bench

FROM alpine:3.18 AS run
WORKDIR /opt/kube-bench/
# add GNU ps for -C, -o cmd, and --no-headers support
# https://github.com/aquasecurity/kube-bench/issues/109
RUN apk --no-cache add procps

# Upgrading apk-tools to remediate CVE-2021-36159 - https://snyk.io/vuln/SNYK-ALPINE314-APKTOOLS-1533752
# https://github.com/aquasecurity/kube-bench/issues/943
RUN apk --no-cache upgrade apk-tools

# Openssl is used by OpenShift tests
# https://github.com/aquasecurity/kube-bench/issues/535
# Ensuring that we update/upgrade before installing openssl, to mitigate CVE-2021-3711 and CVE-2021-3712
RUN apk update && apk upgrade && apk --no-cache add openssl

# Add glibc for running oc command 
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
RUN apk add gcompat
RUN apk add jq

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

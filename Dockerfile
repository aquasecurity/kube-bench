FROM golang:1.23.6 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
COPY makefile makefile
COPY go.mod go.sum ./
COPY main.go .
COPY check/ check/
COPY cmd/ cmd/
COPY internal/ internal/
ARG KUBEBENCH_VERSION
RUN make build && cp kube-bench /go/bin/kube-bench

# Add kubectl to run policies checks
ARG KUBECTL_VERSION TARGETARCH
RUN wget -O /usr/local/bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"
RUN wget -O kubectl.sha256 "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256"

# Verify kubectl sha256sum
RUN /bin/bash -c 'echo "$(<kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum -c -'

RUN chmod +x /usr/local/bin/kubectl

FROM alpine:3.21.2 AS run
WORKDIR /opt/kube-bench/
# add GNU ps for -C, -o cmd, --no-headers support and add findutils to get GNU xargs
# https://github.com/aquasecurity/kube-bench/issues/109
# https://github.com/aquasecurity/kube-bench/issues/1656
RUN apk --no-cache add procps findutils

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

# Add bash for running helper scripts
RUN apk add bash

ENV PATH=$PATH:/usr/local/mount-from-host/bin:/go/bin

COPY --from=build /go/bin/kube-bench /usr/local/bin/kube-bench
COPY --from=build /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY entrypoint.sh .
COPY cfg/ cfg/
COPY helper_scripts/check_files_owner_in_dir.sh /go/bin/
RUN chmod a+x /go/bin/check_files_owner_in_dir.sh
ENTRYPOINT ["./entrypoint.sh"]
CMD ["install"]

# Build-time metadata as defined at http://label-schema.org
ARG BUILD_DATE
ARG VCS_REF
ARG KUBEBENCH_VERSION

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="kube-bench" \
      org.label-schema.vendor="Aqua Security Software Ltd." \
      org.label-schema.version=$KUBEBENCH_VERSION \
      org.label-schema.release=$KUBEBENCH_VERSION \
      org.label-schema.summary="Aqua security server" \
      org.label-schema.maintainer="admin@aquasec.com" \
      org.label-schema.description="Run the CIS Kubernetes Benchmark tests" \
      org.label-schema.url="https://github.com/aquasecurity/kube-bench" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/aquasecurity/kube-bench" \
      org.label-schema.schema-version="1.0"

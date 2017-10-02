FROM golang:1.8
WORKDIR /kube-bench
RUN go get github.com/aquasecurity/kube-bench
RUN cp /go/bin/kube-bench /kube-bench/ && chmod +x /kube-bench/kube-bench
RUN cp -r /go/src/github.com/aquasecurity/kube-bench/cfg cfg

# When Docker Hub supports it, we would split this into a multi-stage build with the second part based on, say, alpine for size
WORKDIR /
ADD entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh

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

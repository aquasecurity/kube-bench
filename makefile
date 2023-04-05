SOURCES := $(shell find . -name '*.go')
BINARY := kube-bench
DOCKER_ORG ?= aquasec
VERSION ?= $(shell git rev-parse --short=7 HEAD)
KUBEBENCH_VERSION ?= $(shell git describe --tags --abbrev=0)
IMAGE_NAME ?= $(DOCKER_ORG)/$(BINARY):$(VERSION)
IMAGE_NAME_UBI ?= $(DOCKER_ORG)/$(BINARY):$(VERSION)-ubi
GOOS ?= linux
BUILD_OS := linux
uname := $(shell uname -s)
BUILDX_PLATFORM ?= linux/amd64,linux/arm64,linux/arm,linux/ppc64le,linux/s390x
DOCKER_ORGS ?= aquasec public.ecr.aws/aquasecurity
GOARCH ?= $@

ifneq ($(findstring Microsoft,$(shell uname -r)),)
	BUILD_OS := windows
else ifeq ($(uname),Linux)
	BUILD_OS := linux
else ifeq ($(uname),Darwin)
	BUILD_OS := darwin
endif

# kind cluster name to use
KIND_PROFILE ?= kube-bench
KIND_CONTAINER_NAME=$(KIND_PROFILE)-control-plane
KIND_IMAGE ?= kindest/node:v1.21.1@sha256:69860bda5563ac81e3c0057d654b5253219618a22ec3a346306239bba8cfa1a6

# build a multi-arch image and push to Docker hub
.PHONY: docker
docker:
	set -xe; \
	for org in $(DOCKER_ORGS); do \
		docker buildx build --tag $${org}/kube-bench:${VERSION} \
		--platform $(BUILDX_PLATFORM) --push . ; \
	done

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=$(GOOS) CGO_ENABLED=0 go build -ldflags "-X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=$(KUBEBENCH_VERSION)" -o $(BINARY) .

# builds the current dev docker version
build-docker:
	docker build --build-arg BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
             --build-arg VCS_REF=$(VERSION) \
			 --build-arg KUBEBENCH_VERSION=$(KUBEBENCH_VERSION) \
             -t $(IMAGE_NAME) .

build-docker-ubi:
	docker build -f Dockerfile.ubi --build-arg BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
             --build-arg VCS_REF=$(VERSION) \
			 --build-arg KUBEBENCH_VERSION=$(KUBEBENCH_VERSION) \
             -t $(IMAGE_NAME_UBI) .

# unit tests
tests:
	GO111MODULE=on go test -vet all -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

integration-test: kind-test-cluster kind-run

# creates a kind cluster to be used for development.
HAS_KIND := $(shell command -v kind;)
kind-test-cluster:
ifndef HAS_KIND
	go get -u sigs.k8s.io/kind
endif
	@if [ -z $$(kind get clusters | grep $(KIND_PROFILE)) ]; then\
		echo "Could not find $(KIND_PROFILE) cluster. Creating...";\
		kind create cluster --name $(KIND_PROFILE) --image $(KIND_IMAGE) --wait 5m;\
	fi

# pushes the current dev version to the kind cluster.
kind-push: build-docker
	kind load docker-image $(IMAGE_NAME) --name $(KIND_PROFILE)

# runs the current version on kind using a job and follow logs
kind-run: KUBECONFIG = "./kubeconfig.kube-bench"
kind-run: kind-push
	sed "s/\$${VERSION}/$(VERSION)/" ./hack/kind.yaml > ./hack/kind.test.yaml
	kind get kubeconfig --name="$(KIND_PROFILE)" > $(KUBECONFIG)
	-KUBECONFIG=$(KUBECONFIG) \
		kubectl delete job kube-bench
	KUBECONFIG=$(KUBECONFIG) \
		kubectl apply -f ./hack/kind.test.yaml && \
		kubectl wait --for=condition=complete job.batch/kube-bench --timeout=60s && \
		kubectl logs job/kube-bench > ./test.data && \
		diff ./test.data integration/testdata/Expected_output.data

kind-run-stig: KUBECONFIG = "./kubeconfig.kube-bench"
kind-run-stig: kind-push
	sed "s/\$${VERSION}/$(VERSION)/" ./hack/kind-stig.yaml > ./hack/kind-stig.test.yaml
	kind get kubeconfig --name="$(KIND_PROFILE)" > $(KUBECONFIG)
	-KUBECONFIG=$(KUBECONFIG) \
		kubectl delete job kube-bench
	KUBECONFIG=$(KUBECONFIG) \
		kubectl apply -f ./hack/kind-stig.test.yaml && \
		kubectl wait --for=condition=complete job.batch/kube-bench --timeout=60s && \
		kubectl logs job/kube-bench > ./test.data && \
		diff ./test.data integration/testdata/Expected_output_stig.data

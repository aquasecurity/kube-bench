SOURCES := $(shell find . -name '*.go')
BINARY := kube-bench
DOCKER_ORG ?= aquasec
VERSION ?= $(shell git rev-parse --short=7 HEAD)
KUBEBENCH_VERSION ?= $(shell git describe --tags --abbrev=0)
IMAGE_NAME ?= $(DOCKER_ORG)/$(BINARY):$(VERSION)
GOOS ?= linux
BUILD_OS := linux
uname := $(shell uname -s)
ARCHS ?= amd64 arm64
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
docker: publish manifests

# build and push an arch-specific image
.PHONY: $(ARCHS) manifests publish
publish: $(ARCHS)
$(ARCHS):
	@echo "Building Docker image for $@"
	docker build -t ${DOCKER_ORG}/${BINARY}:$(GOOS)-$(GOARCH)-${VERSION} \
	--build-arg GOOS=$(GOOS) --build-arg GOARCH=$(GOARCH) ./
	@echo "Push $@ Docker image to ${DOCKER_ORG}/${BINARY}"
	docker push ${DOCKER_ORG}/${BINARY}:$(GOOS)-$(GOARCH)-${VERSION}
	docker manifest create --amend "${DOCKER_ORG}/${BINARY}:${VERSION}" "${DOCKER_ORG}/${BINARY}:$(GOOS)-$(GOARCH)-${VERSION}"
	docker manifest annotate "${DOCKER_ORG}/${BINARY}:${VERSION}" "${DOCKER_ORG}/${BINARY}:$(GOOS)-$(GOARCH)-${VERSION}" --os=$(GOOS) --arch=$(GOARCH)

# push the multi-arch manifest
manifests:
	@echo "Push manifest for ${DOCKER_ORG}/${BINARY}:${VERSION}"
	docker manifest push "${DOCKER_ORG}/${BINARY}:${VERSION}"

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=$(GOOS) go build -ldflags "-X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=$(KUBEBENCH_VERSION)" -o $(BINARY) .

# builds the current dev docker version
build-docker:
	docker build --build-arg BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
             --build-arg VCS_REF=$(VERSION) \
			 --build-arg KUBEBENCH_VERSION=$(KUBEBENCH_VERSION) \
             -t $(IMAGE_NAME) .

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

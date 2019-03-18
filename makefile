SOURCES := $(shell find . -name '*.go')
BINARY := kube-bench
DOCKER_REGISTRY ?= aquasec
VERSION ?= $(shell git rev-parse --short=7 HEAD)
IMAGE_NAME ?= $(DOCKER_REGISTRY)/$(BINARY):$(VERSION)
TARGET_OS := linux
BUILD_OS := linux
uname := $(shell uname -s)

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

build: kube-bench

$(BINARY): $(SOURCES)
	GOOS=$(TARGET_OS) go build -o $(BINARY) .

# builds the current dev docker version
build-docker:
	docker build --build-arg BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
             --build-arg VCS_REF=$(shell git rev-parse --short HEAD) \
             -t $(IMAGE_NAME) .

tests:
	go test -race -timeout 30s -cover ./cmd ./check

# creates a kind cluster to be used for development.
HAS_KIND := $(shell command -v kind;)
kind-test-cluster:
ifndef HAS_KIND
	go get -u sigs.k8s.io/kind
endif
	@if [ -z $$(kind get clusters | grep $(KIND_PROFILE)) ]; then\
		echo "Could not find $(KIND_PROFILE) cluster. Creating...";\
		kind create cluster --name $(KIND_PROFILE) --image kindest/node:v1.11.3 --wait 5m;\
	fi

# pushses the current dev version to the kind cluster.
kind-push:
	docker save $(IMAGE_NAME) -o kube-bench.tar.gz; \
	docker cp kube-bench.tar.gz $(KIND_CONTAINER_NAME):/kube-bench.tar.gz; \
	docker exec $(KIND_CONTAINER_NAME) docker load -i /kube-bench.tar.gz;
	-rm -f kube-bench.tar.gz

# runs the current version on kind using a job and follow logs
kind-run: KUBECONFIG = "$(shell kind get kubeconfig-path --name="$(KIND_PROFILE)")"
kind-run: ensure-stern
	sed "s/\$${VERSION}/$(VERSION)/" ./hack/kind.yaml > ./hack/kind.test.yaml
	-KUBECONFIG=$(KUBECONFIG) \
		kubectl delete job kube-bench 
	KUBECONFIG=$(KUBECONFIG) \
		kubectl apply -f ./hack/kind.test.yaml
	KUBECONFIG=$(KUBECONFIG) \
		stern -l app=kube-bench --container kube-bench

# ensures that stern is installed
HAS_STERN := $(shell command -v stern;)
ensure-stern:
ifndef HAS_STERN
	curl -LO https://github.com/wercker/stern/releases/download/1.10.0/stern_$(BUILD_OS)_amd64 && \
		chmod +rx ./stern_$(BUILD_OS)_amd64 && \
    	mv ./stern_$(BUILD_OS)_amd64 /usr/local/bin/stern
endif

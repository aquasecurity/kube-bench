SOURCES := $(shell find . -name '*.go')
TARGET_OS := linux
BINARY := kube-bench

$(BINARY): $(SOURCES)
	GOOS=$(TARGET_OS) go build -o $(BINARY) .


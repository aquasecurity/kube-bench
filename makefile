SOURCES := $(shell find . -name '*.go')
TARGET_OS := linux

cis_kubernetes: $(SOURCES)
	GOOS=$(TARGET_OS) go build -o cis_kubernetes .

install: cis_kubernetes 
	./install.sh
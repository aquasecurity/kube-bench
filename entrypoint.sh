#!/bin/sh
if [ -d /host ]; then
  mkdir -p /host/cfg/
  yes | cp -rf ./kube-bench/cfg/* /host/cfg/
  yes | cp -rf ./kube-bench/kube-bench /host/
  echo "=== You can now run ./kube-bench from your host ==="
else
  echo "Usage:"
  echo "  docker run --rm -v \`pwd\`:/host aquasec/kube-bench"
  exit 
fi

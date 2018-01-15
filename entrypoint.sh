#!/bin/sh
if [ -d /host ]; then
  mkdir -p /host/cfg/
  yes | cp -rf /cfg/* /host/cfg/
  yes | cp -rf /kube-bench /host/
  echo "==============================================="
  echo "kube-bench is now installed on your host       "
  echo "Run ./kube-bench to perform a security check   "
  echo "==============================================="
else
  echo "Usage:"
  echo "  docker run --rm -v \`pwd\`:/host aquasec/kube-bench"
  exit 
fi

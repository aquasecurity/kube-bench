#!/bin/sh -e
if [ "$1" == "install" ]; then
  if [ -d /host ]; then
    mkdir -p /host/cfg/
    yes | cp -rf cfg/* /host/cfg/
    yes | cp -rf integration/ /host/integration/
    yes | cp -rf /usr/local/bin/kube-bench /host/
    echo "==============================================="
    echo "kube-bench is now installed on your host       "
    echo "Run ./kube-bench to perform a security check   "
    echo "==============================================="
    cat /host/integration/testdata/cis-1.5/job-node.data
  else
    echo "Usage:"
    echo "  install: docker run --rm -v \`pwd\`:/host aquasec/kube-bench install"
    echo "  run:     docker run --rm --pid=host aquasec/kube-bench [command]"
    exit
  fi
else
  exec kube-bench "$@"
fi

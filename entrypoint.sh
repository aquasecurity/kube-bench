#!/bin/sh -e
if [ "$1" == "install" ]; then
  if [ -d /host ]; then
    mkdir -p /host/cfg/
    yes | cp -rf cfg/* /host/cfg/
    yes | cp -rf /usr/local/bin/kube-bench /host/
    echo "==============================================="
    echo "kube-bench is now installed on your host       "
    echo "Run ./kube-bench to perform a security check   "
    echo "==============================================="
  else
    echo "Usage:"
    echo "  install: docker run --rm -v \`pwd\`:/host aquasec/kube-bench install"
    echo "  run:     docker run --rm --pid=host aquasec/kube-bench [command]"
    exit
  fi
elif [ "$1" == "repeat" ]; then
  echo "Now scheduling kube-bench to run every 24 hours"
  touch repeat-logs.txt
  ./repeat-loop.sh > repeat-logs.txt &
else
  exec kube-bench "$@"
fi

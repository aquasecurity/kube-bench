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
else
  if [ -n "$SCHEDULE" ]; then
    echo "$SCHEDULE" "cd $PWD && date && kube-bench" "$@" | crontab -c . -
    crond -c . -f
  else
    kube-bench "$@"
    # If the SCHEDULE variable is not set, the container exits.
    # If set, the container sleeps.
    [ -n "${SCHEDULE+set}" ] && while :; do sleep 1d; done
  fi
fi

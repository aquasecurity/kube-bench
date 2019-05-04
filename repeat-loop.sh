#!/bin/sh -e
while true
do
  exec kube-bench
  sleep 1d
done

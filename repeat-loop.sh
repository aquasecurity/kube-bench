#!/bin/sh -e
while true
do
  $(which kubectl) apply -f job.yaml
  sleep 1d
done

#!/bin/bash

cfgdir="$HOME/.cis_kubernetes"

echo "create cis_kubernetes configuration directory"
mkdir $cfgdir

echo "copy cis_kubernetes configuration file"
cp cfg/config.yaml $cfgdir

echo "copy controls files to configuration directory"
cp cfg/{master,node,federated}.yaml $cfgdir

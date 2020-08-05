#!/bin/bash

#Prepare the .yaml file from the job-node_DaemonSet.yaml.template and kubectl and apply it
function prepare_apply_yaml() {
    unq=$(< /dev/urandom tr -dc a-z-0-9 | head -c 32 | sha256sum | head -c 16)
    template=`cat "job-node_DaemonSet.yaml.template" | sed "s/kube-bench-node/kube-bench-node-${unq}/g"`
    echo "$template" >> job-name_kube-bench-node.yaml
    kubectl apply -f job-name_kube-bench-node.yaml
}

#Fetch logs pod wise and write the scan results to files named node wise
function fetch_write_logs() {
    rm -rf results
    mkdir results
    pod_name="kube-bench-node-${unq}"
    echo "${pod_name}"
    pods=$(kubectl get pods | grep $pod_name | awk -F " " '{print $1}')
    echo $pods
    for pod in ${pods}; do
        node=$(kubectl get pod -o=custom-columns=POD:.metadata.name,NODE:.spec.nodeName --all-namespaces | grep $pod | awk -F " " '{print $2}')
        echo $(date) >> results/$node
        echo "NODE: ${node}" >> results/$node 
        kubectl logs ${pod} >> results/$node
    done
}

# Delete the DaemonSets pods and the Generated .yaml file
function cleanup() {
    kubectl delete -f job-name_kube-bench-node.yaml
    rm job-name_kube-bench-node.yaml
}

prepare_apply_yaml

#Waiting for the pods to spin up and complete
sleep 120

fetch_write_logs

sleep 5 

cleanup

echo "Check Results Directory for the Scan Results"

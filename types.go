package main

type nodeType string

const (
	// MASTER a master node
	MASTER nodeType = "master"
	// NODE a node
	NODE nodeType = "node"
	// FEDERATED a federated deployment.
	FEDERATED nodeType = "federated"
)

package integration

import (
	"os"
	"path/filepath"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
	"sigs.k8s.io/kind/pkg/fs"

	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/errors"
	"sigs.k8s.io/kind/pkg/exec"
)

func loadImageFromDocker(imageName string, provider *cluster.Provider, kindClusterName string) error {
	// Check that the image exists locally and gets its ID, if not return error
	cmd := exec.Command("docker", "inspect", "--format", "{{.Id}}", imageName)
	err := cmd.Run()
	if err != nil {
		return errors.Errorf("Image: %q not present locally", imageName)
	}

	internalNodes, err := provider.ListInternalNodes(kindClusterName)
	if err != nil {
		return err
	}

	var fns []func() error
	// Save the image into a tar
	// Setup the tar path where the images will be saved
	dir, err := fs.TempDir("", "images-tar")
	if err != nil {
		return errors.Wrap(err, "failed to create tempdir")
	}
	defer os.RemoveAll(dir)
	imagesTarPath := filepath.Join(dir, "images.tar")
	// Save the images into a tar
	err = save(imageName, imagesTarPath)
	if err != nil {
		return err
	}

	// Load the images on the selected nodes
	for _, selectedNode := range internalNodes {
		selectedNode := selectedNode // capture loop variable
		fns = append(fns, func() error {
			return loadImage(imagesTarPath, selectedNode)
		})
	}
	return errors.UntilErrorConcurrent(fns)
}

// loads an image tarball onto a node
func loadImage(imageTarName string, node nodes.Node) error {
	f, err := os.Open(imageTarName)
	if err != nil {
		return errors.Wrap(err, "failed to open image")
	}
	defer f.Close()
	return nodeutils.LoadImageArchive(node, f)
}

// save saves images to dest, as in `docker save`
func save(image string, dest string) error {
	commandArgs := append([]string{"save", "-o", dest}, image)
	return exec.Command("docker", commandArgs...).Run()
}

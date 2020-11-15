package integration

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"sigs.k8s.io/kind/pkg/cluster"
	clusternodes "sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/container/docker"
	"sigs.k8s.io/kind/pkg/fs"
	"sigs.k8s.io/kind/pkg/util/concurrent"
)

func loadImageFromDocker(imageName string, kindCtx *cluster.Context) error {

	// Check that the image exists locally and gets its ID, if not return error
	_, err := docker.ImageID(imageName)
	if err != nil {
		return errors.Errorf("Image: %q not present locally", imageName)
	}

	selectedNodes, err := kindCtx.ListInternalNodes()
	if err != nil {
		return err
	}

	// Save the image into a tar
	dir, err := fs.TempDir("", "image-tar")
	if err != nil {
		return errors.Wrap(err, "failed to create tempdir")
	}
	defer os.RemoveAll(dir)
	imageTarPath := filepath.Join(dir, "image.tar")

	err = docker.Save(imageName, imageTarPath)
	if err != nil {
		return err
	}

	// Load the image on the selected nodes
	fns := []func() error{}
	for _, selectedNode := range selectedNodes {
		selectedNode := selectedNode // capture loop variable
		fns = append(fns, func() error {
			return loadImage(imageTarPath, &selectedNode)
		})
	}
	return concurrent.UntilError(fns)
}

// loads an image tarball onto a node
func loadImage(imageTarName string, node *clusternodes.Node) error {
	f, err := os.Open(imageTarName)
	if err != nil {
		return errors.Wrap(err, "failed to open image")
	}
	defer f.Close()
	return node.LoadImageArchive(f)
}

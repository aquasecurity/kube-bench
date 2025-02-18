package integration

import (
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"

	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/exec"
)

func loadImageFromDocker(imageName string, provider *cluster.Provider) error {

	// Check that the image exists locally and gets its ID, if not return error
	cmd := exec.Command("docker", "inspect", "--format", "{{.Id}}", imageName)
	err := cmd.Run()
	if err != nil {
		return errors.Errorf("Image: %q not present locally", imageName)
	}

	nodes, err := provider.ListInternalNodes("kube-bench")
	if err != nil {
		return err
	}

	// Save the image into a tar
	dir, err := os.MkdirTemp("", "image-tar")
	if err != nil {
		return errors.Wrap(err, "failed to create tempdir")
	}
	defer os.RemoveAll(dir)
	imageTarPath := filepath.Join(dir, "image.tar")

	cmd = exec.Command("docker", "save", "-o", imageTarPath, imageName)
	err = cmd.Run()
	if err != nil {
		return err
	}

	// Load the image on the selected nodes
	for _, node := range nodes {
		err := loadImage(imageTarPath, node)
		if err != nil {
			return err
		}
	}

	return nil
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

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var KubeBenchVersion string

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Shows the version of kube-bench.",
	Long:  `Shows the version of kube-bench.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(KubeBenchVersion)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

package cmd

import (
	"github.com/aquasecurity/kube-bench/internal/cisaudit"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(&cobra.Command{
		Use:           "cis-audit [roles|serviceaccounts]",
		Short:         "Collect CIS 1.12 policy evidence with paginated API queries",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fetch, err := cisaudit.APIClient()
			if err != nil {
				return err
			}
			return cisaudit.Run(args[0], fetch, cmd.OutOrStdout())
		},
	})
}

package cmd

import (
	"github.com/spf13/cobra"
)

var serviceSecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage environment variables",
}

func init() {
	serviceCmd.AddCommand(serviceSecretCmd)
}

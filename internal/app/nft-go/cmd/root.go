package cmd

import (
	"fmt"

	app_identity "github.com/H-BF/corlib/app/identity"
	"github.com/spf13/cobra"
)

const (
	appName      = "nft-go"
	shortAppDesc = "Go-native alternative to nft for visualizing nftables rules with familiar syntax"
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Version: fmt.Sprintf("v%s", app_identity.Version),
		Use:     appName,
		Short:   shortAppDesc,
	}
	rootCmd.AddCommand(newlistCommand())
	return rootCmd
}

// Execute root command.
func Execute() {
	_ = newRootCmd().Execute()
}

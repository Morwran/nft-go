package cmd

import (
	"github.com/spf13/cobra"
)

func newlistCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "list",
		Short:   "list one of the nftables object: tables, chains, sets, ruleset",
		Example: "list ruleset",
	}
	c.AddCommand(newTablesCommand(), newChainsCommand(), newSetsCommand(), newRuleSetCommand())
	return c
}

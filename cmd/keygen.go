package cmd

import (
	"aegis/utils"
	"fmt"

	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen [filename]",
	Short: "Generate 256-bit key and save to file",
	Long:  "This command generates a 256-bit key and saves it in .key format. Important! When specifying the [filename] argument, make sure to use the .key extension; otherwise, the encryptor/decryptor will not accept the key.",

	Args: cobra.MaximumNArgs(1),

	RunE: runKeygen,
}

func init() {
	RootCmd.AddCommand(keygenCmd)
}

func runKeygen(cmd *cobra.Command, args []string) error {
	if len(args) == 1 {
		filename := args[0]

		if err := utils.GenerateKey(256, filename); err != nil {
			fmt.Println(err)
			return err
		}

		fmt.Printf("🔑 Key successfully generated and written to file %s", filename)
	} else {
		fmt.Printf("❌ The number of arguments is incorrect! Currently, it's %d, it should be: 1", len(args))
	}
	return nil
}

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "aegis",
	Short: "Aegis — a CLI utility for hiding data within Windows PE files.",
	Long:  "This program is capable of encrypting and decrypting data from pre-prepared PE files. Additionally, with preliminary setup, it can write 256-bit keys to Java Cards.",
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

}

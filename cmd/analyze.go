package cmd

import (
	"aegis/internal/pe"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	analyzeInFile string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Сканує PE-файл та виводить повний список усіх каверн та їхні розміри.",
	Long:  `Сканує секції PE-файлу, знаходить усі доступні каверни, виводить їх таблицею, а також визначає найбільшу каверну.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// 1. Ініціалізація PE-інжектора
		injector, err := pe.New(analyzeInFile)
		if err != nil {
			return fmt.Errorf("помилка при відкритті PE файлу: %w", err)
		}
		defer injector.Close()

		// 2. Отримуємо список ВСІХ каверн
		caverns, err := injector.GetCaverns()
		if err != nil {
			return fmt.Errorf("помилка при пошуку каверн: %w", err)
		}

		if len(caverns) == 0 {
			fmt.Println("[!] У файлі не знайдено жодної каверни.")
			return nil
		}

		// 3. Виводимо таблицю всіх каверн
		fmt.Printf("[+] Результати аналізу PE-файлу: %s\n", analyzeInFile)
		fmt.Println("------------------------------------------------------------------")
		fmt.Printf("%-12s | %-15s | %-18s\n", "Секція", "Розмір каверни (байти)", "Зсув (HEX)")
		fmt.Println("------------------------------------------------------------------")

		var largest pe.Cavern
		isFirst := true

		for _, cav := range caverns {
			fmt.Printf("%-12s | %-15d | 0x%-16X\n", cav.Name, cav.CaveSize, cav.CaveOffset)

			// Шукаємо найбільшу "на льоту" серед усіх знайдених
			if isFirst || cav.CaveSize > largest.CaveSize {
				largest = cav
				isFirst = false
			}
		}

		fmt.Println("------------------------------------------------------------------")

		// 4. Виводимо інформацію про найбільшу каверну
		fmt.Println("\n[★] Найбільша каверна:")
		fmt.Printf("    - Секція       : %s\n", largest.Name)
		fmt.Printf("    - Розмір       : %d байт\n", largest.CaveSize)
		fmt.Printf("    - Зсув (Offset): 0x%X\n", largest.CaveOffset)

		return nil
	},
}

func init() {
	analyzeCmd.Flags().StringVarP(
		&analyzeInFile,
		"in",
		"i",
		"",
		"PE-файл для аналізу каверн (.exe, .dll).",
	)

	_ = analyzeCmd.MarkFlagRequired("in")

	RootCmd.AddCommand(analyzeCmd)
}
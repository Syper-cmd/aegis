package cmd

import (
	"aegis/internal/compress"
	"aegis/internal/crypto"
	"aegis/internal/pe"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	decodeInFile  string
	decodeKeyFile string
	decodeSilent  bool
)

var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Витягує та розшифровує приховані дані з PE файлу.",
	Long:  `Вичитає метадані розміру та зашифрований payload з каверн PE файлу, розшифровує алгоритмом Фейстеля та розпаковує zlib.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// 1. Зчитування та перевірка ключа
		keyBytes, err := os.ReadFile(decodeKeyFile)
		if err != nil {
			return fmt.Errorf("помилка зчитання файлу ключа %s: %w", decodeKeyFile, err)
		}

		if len(keyBytes) != 32 {
			return fmt.Errorf("помилка ключа! Неправильна довжина (%d байт, очікується 32)", len(keyBytes))
		}

		// 2. Ініціалізація PE-інжектора
		decodeInjector, err := pe.New(decodeInFile)
		if err != nil {
			return fmt.Errorf("помилка при відкритті PE файлу: %w", err)
		}
		defer decodeInjector.Close()

		// 3. Знаходимо найбільшу каверну (щоб отримати її CaveOffset і виключити при пошуку найменшої)
		largestCavern, err := decodeInjector.GetLargestCavern()
		if err != nil {
			return fmt.Errorf("помилка при пошуку найбільшої каверни: %w", err)
		}

		// 4. Знаходимо найменшу каверну з метаданими (розміром payload)
		smallestCavern, err := decodeInjector.GetSmallerCavern(largestCavern.CaveOffset)
		if err != nil {
			return fmt.Errorf("помилка при пошуку каверни метаданих: %w", err)
		}

		// 5. Зчитуємо 4 байти розміру payload з найменшої каверни
		sizeBuf := make([]byte, 4)
		if err := decodeInjector.ReadPayload(smallestCavern.CaveOffset, sizeBuf); err != nil {
			return fmt.Errorf("помилка зчитання розміру payload: %w", err)
		}

		payloadSize := binary.BigEndian.Uint32(sizeBuf)
		if payloadSize == 0 {
			return fmt.Errorf("помилка: зчитаний розмір payload дорівнює 0 (можливо, файл не містить даних)")
		}

		// 6. Зчитуємо зашифрований payload з найбільшої каверни
		encryptedPayload := make([]byte, payloadSize)
		if err := decodeInjector.ReadPayload(largestCavern.CaveOffset, encryptedPayload); err != nil {
			return fmt.Errorf("помилка зчитання зашифрованого payload: %w", err)
		}

		// 7. Ініціалізація шифра та розшифрування
		feistelCipher, err := crypto.NewFeistelCipher(keyBytes)
		if err != nil {
			return fmt.Errorf("помилка при створенні шифра: %w", err)
		}

		compressedPayload, err := feistelCipher.Decrypt(encryptedPayload)
		if err != nil {
			return fmt.Errorf("помилка розшифрування даних: %w", err)
		}

		// 8. Розпакування zlib
		decompressedText, err := compress.DecompressZlib(compressedPayload)
		if err != nil {
			return fmt.Errorf("помилка розархівації zlib: %w", err)
		}

		// 9. Вивід результату
		if !decodeSilent {
			fmt.Println("[+] Дані успішно витягнуто та розшифровано!")
			fmt.Printf("    - Зчитано %d байт з %s (CaveOffset: 0x%X)\n", payloadSize, largestCavern.Name, largestCavern.CaveOffset)
			fmt.Println("\nРозшифрований текст:")
		}

		fmt.Println(string(decompressedText))

		return nil
	},
}

func init() {
	decodeCmd.Flags().StringVarP(
		&decodeInFile,
		"in",
		"i",
		"",
		"PE файл, з якого потрібно витягнути приховані дані.",
	)
	decodeCmd.Flags().StringVarP(
		&decodeKeyFile,
		"key",
		"k",
		"",
		"Ключ для розшифрування (.key).",
	)
	decodeCmd.Flags().BoolVarP(
		&decodeSilent,
		"silent",
		"s",
		false,
		"Тихий режим — виводить у stdout ТІЛЬКИ розшифрований текст без службових логів.",
	)

	_ = decodeCmd.MarkFlagRequired("in")
	_ = decodeCmd.MarkFlagRequired("key")

	RootCmd.AddCommand(decodeCmd)
}
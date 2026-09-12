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
	inFile       string
	keyFile      string
	silent       bool
	textToEncode string
)

var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Шифрує дані в PE файл.",
	Long:  `Шифрує текст за допомогою алгоритму на основі мережі Фейстеля, а потім записує в каверни в PE файлі.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// 1. Зчитування ключа
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("помилка зчитання файлу ключа %s: %w", keyFile, err)
		}

		if len(keyBytes) != 32 {
			return fmt.Errorf("помилка ключа! Неправильна довжина (%d байт, очікується 32)", len(keyBytes))
		}

		// 2. Стиснення даних
		compressedTextToEncode, err := compress.CompressZlib([]byte(textToEncode))
		if err != nil {
			return fmt.Errorf("помилка стискання тексту: %w", err)
		}

		// 3. Ініціалізація шифра та шифрування
		feistelSifrConst, err := crypto.NewFeistelCipher(keyBytes)
		if err != nil {
			return fmt.Errorf("помилка при створенні структури шифра: %w", err)
		}

		encryptedPayload := feistelSifrConst.Encrypt(compressedTextToEncode)

		// 4. Ініціалізація інжектора PE
		encodeInjector, err := pe.New(inFile)
		if err != nil {
			return fmt.Errorf("помилка при відкритті PE файлу: %w", err)
		}
		defer encodeInjector.Close()

		// 5. Пошук найбільшої каверни під payload
		largestCavern, err := encodeInjector.GetLargestCavern()
		if err != nil {
			return fmt.Errorf("помилка при отриманні найбільшої каверни: %w", err)
		}

		payloadLen := len(encryptedPayload)

		// Перевірка розміру каверни та реалізація поведінки залежно від silent
		if payloadLen > largestCavern.CaveSize {
			if silent {
				return fmt.Errorf("помилка: payload (%d байт) перевищує доступну каверну найбільшої секції (%d байт). У режимі --silent розширення заборонено", payloadLen, largestCavern.CaveSize)
			}

			// У звичайному режимі розширюємо секцію
			neededBytes := payloadLen - largestCavern.CaveSize
			fmt.Printf("[!] Payload (%d B) не вміщується в каверну (%d B). Розширюємо секцію %s...\n",
				payloadLen, largestCavern.CaveSize, largestCavern.Name)

			if err := encodeInjector.ExpandSectionRawSize(largestCavern.Name, neededBytes); err != nil {
				return fmt.Errorf("помилка розширення секції: %w", err)
			}

			// Перечитаємо оновлені параметри каверни після розширення
			largestCavern, err = encodeInjector.GetLargestCavern()
			if err != nil {
				return fmt.Errorf("помилка оновлення даних каверни: %w", err)
			}
		}

		// 6. Пошук найменшої каверни під розмір (ігноруємо найбільшу)
		smallestCavern, err := encodeInjector.GetSmallerCavern(largestCavern.CaveOffset)
		if err != nil {
			return fmt.Errorf("помилка при отриманні каверни під метадані: %w", err)
		}

		// 7. Упаковка довжини у 4 байти
		sizeBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(sizeBuf, uint32(payloadLen))

		// 8. Запис метаданих та payload у відповідні CaveOffset
		if err := encodeInjector.WritePayload(smallestCavern.CaveOffset, sizeBuf); err != nil {
			return fmt.Errorf("помилка запису розміру: %w", err)
		}

		if err := encodeInjector.WritePayload(largestCavern.CaveOffset, encryptedPayload); err != nil {
			return fmt.Errorf("помилка запису payload: %w", err)
		}

		fmt.Println("[+] Все пройшло успішно!")
		fmt.Printf("    - Payload (%d байт) -> %s (CaveOffset: 0x%X)\n", payloadLen, largestCavern.Name, largestCavern.CaveOffset)
		fmt.Printf("    - Метадані (4 байти) -> %s (CaveOffset: 0x%X)\n", smallestCavern.Name, smallestCavern.CaveOffset)

		return nil
	},
}

func init() {
	encodeCmd.Flags().StringVarP(
		&inFile,
		"in",
		"i",
		"",
		`Файл, в якому будуть шукати каверни, та використовувати як основу. Зміни записуються в файл.
Точно підтримуються: .exe
На перевірці: .dll`,
	)
	encodeCmd.Flags().StringVarP(
		&textToEncode,
		"text",
		"t",
		"",
		"Текст для шифрування та скриття.",
	)
	encodeCmd.Flags().StringVarP(
		&keyFile,
		"key",
		"k",
		"",
		"Ключ, який використовується для шифрування та розшифрування файлів (.key).",
	)
	encodeCmd.Flags().BoolVarP(
		&silent,
		"silent",
		"s",
		false,
		"Тихий режим — приховує вивід деталей у консоль та не розширює файли при нестачі каверни.",
	)

	_ = encodeCmd.MarkFlagRequired("in")
	_ = encodeCmd.MarkFlagRequired("text")
	_ = encodeCmd.MarkFlagRequired("key")

	RootCmd.AddCommand(encodeCmd)
}

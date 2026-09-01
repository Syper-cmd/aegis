package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	inFile       string
	outFile      string
	keyFile      string
	silent       bool
	textToEncode string
)

var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Шифрує данні в PE файл.",
	Long:  `Шифрує текст за допомогою алгоритму на основі мережі Фейстеля, а потім записує в каверни в PE файлі.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		// 1. Исправлено: убрали, теперь считывается весь файл ключа целиком
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("Помилка зчитання файлу ключа %s. Помилка: %w", keyFile, err)
		}

		// 2. Исправлено: корректно возвращаем форматированную строку ошибки
		if len(keyBytes) != 32 {
			return fmt.Errorf("Помилка зчитування файлу ключа! Неправильна довжина (%d байт). Можливо, ключ було згенеровано іншою программою, або він пошкодженний.", len(keyBytes))
		}

		// TODO:  Do a encode logic

		return nil
	},
}

func init() {
	encodeCmd.Flags().StringVarP(
		&inFile,
		"in",
		"i",
		"",
		`Файл, в якому будуть шукати каверни, та використовувати як основу. Сам файл не змінюється.
		Точно підтримуються: .exe
		На перевірці: .dll`,
	)
	encodeCmd.Flags().StringVarP(
		&outFile,
		"out",
		"o",
		"",
		`Файл, який буде зберігатися на компьютері.
		Це файл, в якому буде вже записанний та зашифрованний текст.
		Для основи використовуеться файл з -in.`,
	)
	encodeCmd.Flags().StringVarP(
		&textToEncode,
		"text",
		"t",
		"",
		"Текст для шифрування та скриття. Цей текст пройде етап стиснення та шифрування, а після буде записанний в каверни.",
	)

	encodeCmd.Flags().StringVarP(
		&keyFile,
		"key",
		"k",
		"",
		`Ключ, який використовується для шифрування та розшифрування файлів. Має бути сгенерований командою keygen.
		Тип ключів, які підтримує программа: .key, сгенеровані командою keygen`,
	)

	encodeCmd.Flags().BoolVarP(
		&silent,
		"silent",
		"s",
		false,
		`Тихий режим - режим, що дозволяє не змінювати розмір файлу.
		Якщо каверни в файлі будуть меньші, за текст, программа не буде розширювати файл, а видасть попередження.`,
	)

	_ = encodeCmd.MarkFlagRequired("in")
	_ = encodeCmd.MarkFlagRequired("out")
	_ = encodeCmd.MarkFlagRequired("text")
	_ = encodeCmd.MarkFlagRequired("key")

	RootCmd.AddCommand(encodeCmd)
}

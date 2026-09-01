package main

import (
	"aegis/internal/crypto"
	"encoding/csv"
	"fmt"
	"math/bits"
	"os"
	"strconv"
	"time"

	"github.com/briandowns/spinner"
	// Заміни на свій шлях до пакета crypto
)

// Перевірочні тексти (3 різних за типом рядки)
var sampleTexts = []string{
	"Hello World! This is a test string for crypto.",   // Англійська мова
	"Слава Україні! Тестування лавинного ефекту МАН.",  // Кирилиця
	"012345678901234567890123456789012345678901234567", // Числа / Бінарні
	"Hello! My name это Саша. Мой phone is 0982205873",
}

func main() {
	s := spinner.New(spinner.CharSets[21], 100*time.Millisecond)
	s.Start()
	key := make([]byte, 32) // 256-бітний тестовий ключ
	for i := range key {
		key[i] = byte(i * 7)
	}
	s.Stop()

	cipher, err := crypto.NewFeistelCipher(key)
	if err != nil {
		panic(err)
	}

	// Створюємо CSV файл
	file, err := os.Create("results.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Заголовок CSV
	_ = writer.Write([]string{"sample_id", "round", "bit_difference_pct"})

	s.Start()

	for sampleID, originalText := range sampleTexts {
		origBytes := []byte(originalText)[:8] // Беремо перший блок 8 байт

		// Створюємо мутований текст (змінюємо 1 біт у першому байті)
		mutatedBytes := make([]byte, len(origBytes))
		copy(mutatedBytes, origBytes)
		mutatedBytes[0] ^= 0x01 // Перевертаємо 1 біт через XOR

		// Порівнюємо раунд за раундом
		for r := 1; r <= crypto.NumRounds; r++ {
			out1 := encryptPartialRounds(cipher, origBytes, r)
			out2 := encryptPartialRounds(cipher, mutatedBytes, r)

			pct := countBitDifference(out1, out2)

			_ = writer.Write([]string{
				strconv.Itoa(sampleID + 1),
				strconv.Itoa(r),
				fmt.Sprintf("%.2f", pct),
			})
		}
	}

	s.Stop()

	fmt.Println("✅ Результати успішно збережено в avalanche_results.csv")
}

// Емуляція шифрування до конкретного раунду N
func encryptPartialRounds(c *crypto.FeistelCipher, block []byte, maxRound int) []byte {
	out := make([]byte, 8)
	c.EncryptBlockRounds(block, out, maxRound)
	return out
}

// Обчислення відсотка відмінностей бітів (Hamming Distance)
func countBitDifference(b1, b2 []byte) float64 {
	totalBits := len(b1) * 8
	diffBits := 0

	for i := 0; i < len(b1); i++ {
		diffBits += bits.OnesCount8(b1[i] ^ b2[i])
	}

	return (float64(diffBits) / float64(totalBits)) * 100.0
}

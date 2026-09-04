package tests

import (
	"aegis/internal/crypto"
	"crypto/rand"
	"testing"
)

func TestEncDec(t *testing.T) {
	key := make([]byte, crypto.KeySize256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Помилка генерації ключа: %v", err)
	}

	cipher, err := crypto.NewFeistelCipher(key)

	if err != nil {
		t.Fatalf("Ошибка генерации структуры: %v", err)
	}

	testText := []byte("Альфа бета гамма штрих.")
	encText := cipher.Encrypt(testText)

	decText, err := cipher.Decrypt(encText)

	if err != nil {
		t.Fatalf("Ошибка розшифровки:, %v", err)
	}

	if string(testText) != string(decText) {
		t.Fatalf("ОШИБКА! СТРОКИ НЕ СОВПАЛИ! Ожидалось: %s, Получил:%s", testText, decText)
	}
}

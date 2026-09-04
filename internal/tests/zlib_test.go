package tests

import (
	"aegis/internal/compress"
	"testing"
)

func TestZlib(t *testing.T) {
	original := []byte("Альфа гамма бета штрих.")

	compressed, err := compress.CompressZlib(original)

	if err != nil {
		t.Fatalf("Ошибка сжатия: %v", err)
	}

	decompressed, err := compress.DecompressZlib(compressed)
	if err != nil {
		t.Fatalf("Ошибка расжатия: %v", err)
	}

	if string(original) != string(decompressed) {
		t.Fatalf("Ошибка! Ожидалось: %s, а вышло: %s", string(original), string(decompressed))
	}
}

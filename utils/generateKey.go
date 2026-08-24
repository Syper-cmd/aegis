package utils

import (
	"crypto/rand"
	"errors"
	"os"
)

func GenerateKey(lengthInBits int, filename string) error {
	key := make([]byte, lengthInBits/8)
	if _, err := rand.Read(key); err != nil {
		return errors.New("Error generating key. Please try again.")
	}

	if err := os.WriteFile(filename, key, 0600); err != nil {
		return errors.New("Error writing the file. Please check the script's access permissions.")
	}

	return nil
}

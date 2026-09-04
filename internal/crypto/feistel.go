package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	BlockSize  = 8  // 64 біти (32 біти L + 32 біти R)
	NumRounds  = 16 // Стандартна кількість раундів Фейстеля
	KeySize256 = 32 // 256 біт = 32 байти
)

// 4-бітна нелінійна таблиця підстановки (S-Box) для руйнування лінійності
var sBox = [16]uint8{
	0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
	0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
}

type FeistelCipher struct {
	subkeys [NumRounds]uint32
}

// NewFeistelCipher створює шифр із 256-бітного ключа
func NewFeistelCipher(key []byte) (*FeistelCipher, error) {
	if len(key) != KeySize256 {
		return nil, errors.New("ключ має бути суворо 256 біт (32 байти)")
	}

	c := &FeistelCipher{}
	c.generateSubkeys(key)
	return c, nil
}

// Key Schedule: генерація 16 subkeys із 256-бітного ключа через SHA-256
func (c *FeistelCipher) generateSubkeys(key []byte) {
	for i := 0; i < NumRounds; i++ {
		h := sha256.New()
		h.Write(key)
		h.Write([]byte{byte(i)})
		hash := h.Sum(nil)
		c.subkeys[i] = binary.BigEndian.Uint32(hash[:4])
	}
}

// Ускладнена F-функція (ARX + S-Box + Bitwise Rotation)
func (c *FeistelCipher) f(r uint32, subkey uint32) uint32 {
	// 1. Нелінійне комбінування додавання (+ mod 2^32) та XOR із раундовим ключем
	x := (r + subkey) ^ 0x9E3779B9

	// 2. S-Box підстановка для молодшого півбайта (нібла)
	nibble := x & 0x0F
	substituted := (x & 0xFFFFFFF0) | uint32(sBox[nibble])

	// 3. Циклічний зсув бітів ліворуч на 13 позицій (забезпечує швидкий лавинний ефект)
	rotated := bits.RotateLeft32(substituted, 13)

	// 4. Фінальне множення для додаткового перемішування бітових розрядів
	return rotated * 0x85EBCA6B
}

// EncryptBlock шифрує 1 блок (8 байт)
func (c *FeistelCipher) EncryptBlock(src, dst []byte) {
	L := binary.BigEndian.Uint32(src[:4])
	R := binary.BigEndian.Uint32(src[4:8])

	for i := 0; i < NumRounds; i++ {
		L, R = R, L^c.f(R, c.subkeys[i])
	}

	binary.BigEndian.PutUint32(dst[:4], R) // Фінальна перестановка L/R
	binary.BigEndian.PutUint32(dst[4:8], L)
}

// EncryptBlockRounds шифрує 1 блок лише до вказаного раунду maxRounds (для збору метрик)
func (c *FeistelCipher) EncryptBlockRounds(src, dst []byte, maxRounds int) {
	L := binary.BigEndian.Uint32(src[:4])
	R := binary.BigEndian.Uint32(src[4:8])

	for i := 0; i < maxRounds && i < NumRounds; i++ {
		L, R = R, L^c.f(R, c.subkeys[i])
	}

	binary.BigEndian.PutUint32(dst[:4], R)
	binary.BigEndian.PutUint32(dst[4:8], L)
}

// Encrypt шифрує масив байтів із використанням PKCS7 padding
func (c *FeistelCipher) Encrypt(data []byte) []byte {
	padded := pkcs7Pad(data, BlockSize)
	encrypted := make([]byte, len(padded))

	for i := 0; i < len(padded); i += BlockSize {
		c.EncryptBlock(padded[i:i+BlockSize], encrypted[i:i+BlockSize])
	}
	return encrypted
}

// DecryptBlock розшифровує 1 блок (8 байт)
// DecryptBlock розшифровує 1 блок (8 байт)
func (c *FeistelCipher) DecryptBlock(src, dst []byte) {
	// Правильно зчитуємо половинки:
	// src[:4] відповідає L для алгоритму розшифрування (колишнє R)
	// src[4:8] відповідає R для алгоритму розшифрування (колишнє L)
	L := binary.BigEndian.Uint32(src[:4])
	R := binary.BigEndian.Uint32(src[4:8])

	// Крутимо раундові ключі у ЗВОРОТНОМУ порядку!
	for i := NumRounds - 1; i >= 0; i-- {
		L, R = R, L^c.f(R, c.subkeys[i])
	}

	// Фінальний запис відновлених оригінальних блоків
	binary.BigEndian.PutUint32(dst[:4], R)
	binary.BigEndian.PutUint32(dst[4:8], L)
}

// Decrypt розшифровує масив байтів та знімає PKCS7 padding
func (c *FeistelCipher) Decrypt(data []byte) ([]byte, error) {
	if len(data)%BlockSize != 0 || len(data) == 0 {
		return nil, errors.New("некоректна довжина зашифрованого блоку")
	}

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += BlockSize {
		c.DecryptBlock(data[i:i+BlockSize], decrypted[i:i+BlockSize])
	}

	return pkcs7Unpad(decrypted)
}

// PKCS7 Padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpad видаляє додаткові байти падінгу
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("порожні дані")
	}

	unpadding := int(data[length-1])
	if unpadding > BlockSize || unpadding == 0 {
		return nil, errors.New("некоректний падінг")
	}

	return data[:(length - unpadding)], nil
}

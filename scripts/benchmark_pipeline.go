package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"time"
)

const (
	blockSize  = 8
	numRounds  = 16
	keySize256 = 32
)

var sBox = [16]uint8{
	0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
	0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
}

type feistelCipher struct {
	subkeys [numRounds]uint32
}

func newFeistel(key []byte) *feistelCipher {
	c := &feistelCipher{}
	for i := 0; i < numRounds; i++ {
		h := sha256.New()
		h.Write(key)
		h.Write([]byte{byte(i)})
		sum := h.Sum(nil)
		c.subkeys[i] = binary.BigEndian.Uint32(sum[:4])
	}
	return c
}

func (c *feistelCipher) f(r, subkey uint32) uint32 {
	x := (r + subkey) ^ 0x9E3779B9
	nibble := x & 0x0F
	substituted := (x & 0xFFFFFFF0) | uint32(sBox[nibble])
	rotated := bits.RotateLeft32(substituted, 13)
	return rotated * 0x85EBCA6B
}

func (c *feistelCipher) encryptBlock(src, dst []byte) {
	L := binary.BigEndian.Uint32(src[:4])
	R := binary.BigEndian.Uint32(src[4:8])
	for i := 0; i < numRounds; i++ {
		L, R = R, L^c.f(R, c.subkeys[i])
	}
	binary.BigEndian.PutUint32(dst[:4], R)
	binary.BigEndian.PutUint32(dst[4:8], L)
}

func pkcs7Pad(data []byte, bs int) []byte {
	pad := bs - (len(data) % bs)
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func (c *feistelCipher) encrypt(data []byte) []byte {
	padded := pkcs7Pad(data, blockSize)
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += blockSize {
		c.encryptBlock(padded[i:i+blockSize], out[i:i+blockSize])
	}
	return out
}

func zlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(data); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type cave struct {
	offset uint32
	size   int
	name   string
}

func findCaverns(path string) (largest, smaller *cave, err error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var caves []cave
	for _, sec := range f.Sections {
		if sec.Size > sec.VirtualSize {
			caves = append(caves, cave{
				offset: sec.Offset + sec.VirtualSize,
				size:   int(sec.Size - sec.VirtualSize),
				name:   sec.Name,
			})
		}
	}
	if len(caves) == 0 {
		return nil, nil, fmt.Errorf("каверн не знайдено")
	}

	li := 0
	for i := range caves {
		if caves[i].size > caves[li].size {
			li = i
		}
	}
	largest = &caves[li]

	for i := range caves {
		if caves[i].offset != largest.offset {
			smaller = &caves[i]
			break
		}
	}
	return largest, smaller, nil
}

func main() {
	writeFlag := flag.Bool("write", false, "реально записувати дані у PE (за замовчуванням dry-run)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Використання:")
		fmt.Println("  go run scripts/benchmark_pipeline.go <pe_file> [payload_file] [-write]")
		os.Exit(1)
	}

	pePath := args[0]
	payload := []byte("Aegis benchmark payload — тестові дані для вимірювання швидкодії конвеєра zlib + Feistel + write")
	if len(args) > 1 {
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "не вдалося прочитати payload: %v\n", err)
			os.Exit(1)
		}
		payload = data
	}

	fmt.Printf("Контейнер : %s\n", filepath.Base(pePath))
	fmt.Printf("Payload   : %d байт\n", len(payload))
	fmt.Printf("Режим     : %s\n\n", map[bool]string{false: "dry-run", true: "WRITE"}[*writeFlag])

	start := time.Now()
	largest, smaller, err := findCaverns(pePath)
	tParse := time.Since(start).Seconds() * 1000
	if err != nil {
		fmt.Fprintf(os.Stderr, "парсинг: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("C_max     : %d байт (offset 0x%X)\n", largest.size, largest.offset)
	if smaller != nil {
		fmt.Printf("C_aux     : %d байт (offset 0x%X)\n", smaller.size, smaller.offset)
	}

	start = time.Now()
	compressed, err := zlibCompress(payload)
	tZlib := time.Since(start).Seconds() * 1000
	if err != nil {
		fmt.Fprintf(os.Stderr, "zlib: %v\n", err)
		os.Exit(1)
	}

	key := make([]byte, keySize256)
	for i := range key {
		key[i] = byte(i * 7)
	}
	cipher := newFeistel(key)

	start = time.Now()
	encrypted := cipher.encrypt(compressed)
	tFeistel := time.Since(start).Seconds() * 1000

	var tWrite float64
	if *writeFlag {
		start = time.Now()
		if err := writeAt(pePath, largest.offset, encrypted); err != nil {
			fmt.Fprintf(os.Stderr, "запис payload: %v\n", err)
		}
		if smaller != nil && smaller.size >= 4 {
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
			if err := writeAt(pePath, smaller.offset, lenBuf); err != nil {
				fmt.Fprintf(os.Stderr, "запис length: %v\n", err)
			}
		}
		tWrite = time.Since(start).Seconds() * 1000
	} else {
		start = time.Now()
		_ = len(encrypted)
		tWrite = time.Since(start).Seconds() * 1000
	}

	total := tParse + tZlib + tFeistel + tWrite

	fmt.Println()
	fmt.Printf("%-12s %8s\n", "Етап", "мс")
	fmt.Println("----------------------")
	fmt.Printf("%-12s %8.2f\n", "Парсинг", tParse)
	fmt.Printf("%-12s %8.2f\n", "zlib", tZlib)
	fmt.Printf("%-12s %8.2f\n", "Feistel", tFeistel)
	fmt.Printf("%-12s %8.2f\n", "Запис", tWrite)
	fmt.Println("----------------------")
	fmt.Printf("%-12s %8.2f\n", "Загалом", total)
	fmt.Printf("\nРозмір після zlib+Feistel: %d байт (було %d)\n", len(encrypted), len(payload))
}

func writeAt(path string, offset uint32, data []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Seek(int64(offset), io.SeekStart); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

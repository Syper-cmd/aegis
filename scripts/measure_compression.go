// measure_compression.go
// Допоміжний скрипт для відтворення даних Додатку Г.2
// (ефективність попереднього стиснення zlib + ентропія Шеннона).
//
// Використання:
//
//	go run scripts/measure_compression.go
//	go run scripts/measure_compression.go payload.bin   # додатково перевірити свій файл
package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// shannonEntropy обчислює ентропію Шеннона у бітах на байт.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make(map[byte]int, 256)
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		if p > 0 {
			h -= p * math.Log2(p)
		}
	}
	return h
}

// zlibCompress стискає дані з максимальним рівнем стиснення.
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

func testPayload(name string, data []byte) {
	compressed, err := zlibCompress(data)
	if err != nil {
		fmt.Printf("%-35s | ERROR: %v\n", name, err)
		return
	}

	hRaw := shannonEntropy(data)
	hZlib := shannonEntropy(compressed)

	kComp := 0.0
	if len(compressed) > 0 {
		kComp = float64(len(data)) / float64(len(compressed))
	}
	gain := (kComp - 1.0) * 100.0
	if kComp < 1.0 {
		gain = 0.0
	}

	fmt.Printf("%-35s | %6d | %6d | %5.2f | %5.2f | %5.2f | %+6.0f%%\n",
		name, len(data), len(compressed), kComp, hRaw, hZlib, gain)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("%-35s | %6s | %6s | %5s | %5s | %5s | %s\n",
		"Тип навантаження", "Вхід", "zlib", "K", "H_raw", "H_zlib", "Приріст")
	fmt.Println("------------------------------------------------------------------------------------------------")

	// 1. JSON / токени (висока надмірність)
	jsonData := bytes.Repeat([]byte(
		`{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example","user":"admin","role":"root","exp":1735689600}`,
	), 30)
	if len(jsonData) > 2450 {
		jsonData = jsonData[:2450]
	}
	testPayload("JSON конфігурація / Токени", jsonData)

	// 2. Вихідний код
	code := bytes.Repeat([]byte(
		"package main\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"Hello, Aegis\")\n}\n",
	), 90)
	if len(code) > 4120 {
		code = code[:4120]
	}
	testPayload("Вихідний код C / Go", code)

	// 3. Текстовий документ
	text := bytes.Repeat([]byte(
		"Це приклад текстового документа українською мовою з повторюваними фрагментами. ",
	), 50)
	if len(text) > 3100 {
		text = text[:3100]
	}
	testPayload("Текстовий документ TXT", text)

	// 4. Криптографічні ключі (середня/висока ентропія)
	keys := make([]byte, 1024)
	rand.Read(keys)
	testPayload("Криптографічні ключі RSA/ECC", keys)

	// 5. Повністю випадковий шум
	noise := make([]byte, 1000)
	rand.Read(noise)
	testPayload("Зашумлений бінарний масив", noise)

	// Додатково: користувацький файл
	if len(os.Args) > 1 {
		data, err := os.ReadFile(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "не вдалося прочитати %s: %v\n", os.Args[1], err)
		} else {
			testPayload("Файл: "+filepath.Base(os.Args[1]), data)
		}
	}
}

// benchmark
package main

import (
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type CaveInfo struct {
	Name     string
	CaveSize int
}

func analyzePE(path string) (totalSize int64, sections int, caves []CaveInfo, cTotal int, err error) {
	f, err := pe.Open(path)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	defer f.Close()

	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	totalSize = fi.Size()
	sections = len(f.Sections)

	for _, sec := range f.Sections {
		if sec.Size > sec.VirtualSize {
			size := int(sec.Size - sec.VirtualSize)
			caves = append(caves, CaveInfo{
				Name:     strings.TrimRight(sec.Name, "\x00"),
				CaveSize: size,
			})
			cTotal += size
		}
	}

	sort.Slice(caves, func(i, j int) bool {
		return caves[i].CaveSize > caves[j].CaveSize
	})
	return
}

func collectFiles(args []string) []string {
	var files []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "попередження: не вдалося відкрити %s: %v\n", arg, err)
			continue
		}
		if info.IsDir() {
			_ = filepath.Walk(arg, func(p string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(p))
				if ext == ".exe" || ext == ".dll" || ext == ".sys" {
					files = append(files, p)
				}
				return nil
			})
		} else {
			files = append(files, arg)
		}
	}
	return files
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Використання:")
		fmt.Println("  go run scripts/measure_capacity.go <file1.exe> [file2.dll] ...")
		fmt.Println("  go run scripts/measure_capacity.go ./samples/")
		os.Exit(1)
	}

	files := collectFiles(os.Args[1:])
	if len(files) == 0 {
		fmt.Println("Не знайдено жодного PE-файла.")
		os.Exit(1)
	}

	fmt.Printf("%-4s %-22s %12s %8s %8s %12s %10s\n",
		"№", "Файл", "F_total", "Секцій", "Каверн", "C_total", "η_cap")
	fmt.Println(strings.Repeat("-", 82))

	for i, path := range files {
		total, secs, caves, cTotal, err := analyzePE(path)
		name := filepath.Base(path)
		if err != nil {
			fmt.Printf("%-4d %-22s  ERROR: %v\n", i+1, name, err)
			continue
		}
		eta := 0.0
		if total > 0 {
			eta = float64(cTotal) / float64(total) * 100.0
		}
		fmt.Printf("%-4d %-22s %12d %8d %8d %12d %9.2f%%\n",
			i+1, name, total, secs, len(caves), cTotal, eta)

		if len(caves) > 0 {
			fmt.Printf("     → C_max = %d байт (секція %q)\n", caves[0].CaveSize, caves[0].Name)
		}
	}
}

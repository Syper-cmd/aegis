package pe

import (
	"debug/pe"
	"fmt"
)

type Injector struct {
	filePath string
	peFile   *pe.File
}

type SectionData struct {
	Name        string // Ім'я секції
	PhysSize    uint32 // Фізичний розмір данних
	VirtualSize uint32 // "Віртуальний" розмір данних
	Offset      uint32 // Зсув для пошуку секції
	CaveOffset  uint32 // Зсув каверни
	CaveSize    int    // Розмір каверни
}

func New(filePath string) (*Injector, error) {
	peFile, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("Виникла помилка відкриття PE файлу: %v", err)
	}

	return &Injector{
		filePath: filePath,
		peFile:   peFile,
	}, nil
}

func (inj Injector) Close() error {
	if inj.peFile != nil {
		return inj.peFile.Close()
	}

	return fmt.Errorf("Помилка! PE файл не був відкритий")
}

func (inj Injector) GetLargestCavern() (*SectionData, error) {
	sections, err := inj.GetSectionDebugInfo()

	if err != nil {
		return nil, fmt.Errorf("Виникла помилка отримання секцій: %v", err)
	}

	largestSection := sections[0]

	for _, secData := range sections[1:] {
		if secData.CaveSize > largestSection.CaveSize {
			largestSection = secData
		}
	}

	return &largestSection, nil
}

func (inj Injector) WritePayload() error {

	return nil
}

func (inj Injector) GetSectionDebugInfo() ([]SectionData, error) {
	if inj.peFile == nil {
		return nil, fmt.Errorf("Помилка! PE файл не було відкрито.")
	}
	results := []SectionData{}

	for _, sec := range inj.peFile.Sections {
		cavernSize := -1

		if sec.Size > sec.VirtualSize {
			cavernSize = int(sec.Size) - int(sec.VirtualSize)
		}

		results = append(results, SectionData{
			Name:        sec.Name,
			PhysSize:    sec.Size,
			VirtualSize: sec.VirtualSize,
			Offset:      sec.Offset,
			CaveOffset:  sec.Offset + sec.VirtualSize,
			CaveSize:    cavernSize,
		})
	}

	return results, nil
}

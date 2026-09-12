package pe

import (
	"debug/pe"
	"fmt"
	"os"
)

type Injector struct {
	filePath string
	peFile   *pe.File
}

type SectionData struct {
	Name        string // Ім'я секції
	PhysSize    uint32 // Фізичний розмір даних
	VirtualSize uint32 // "Віртуальний" розмір даних
	Offset      uint32 // Зсув для пошуку секції
	CaveOffset  uint32 // Зсув каверни
	CaveSize    int    // Розмір каверни
}

func New(filePath string) (*Injector, error) {
	peFile, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("виникла помилка відкриття PE файлу: %w", err)
	}

	return &Injector{
		filePath: filePath,
		peFile:   peFile,
	}, nil
}

// Всі методи робимо з ресивером (inj *Injector)
func (inj *Injector) Close() error {
	if inj.peFile != nil {
		err := inj.peFile.Close()
		inj.peFile = nil
		return err
	}
	return nil
}

func (inj *Injector) GetSectionDebugInfo() ([]SectionData, error) {
	if inj.peFile == nil {
		return nil, fmt.Errorf("помилка! PE файл не було відкрито")
	}

	var results []SectionData

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

func (inj *Injector) GetLargestCavern() (*SectionData, error) {
	sections, err := inj.GetSectionDebugInfo()
	if err != nil {
		return nil, fmt.Errorf("виникла помилка отримання секцій: %w", err)
	}

	if len(sections) == 0 {
		return nil, fmt.Errorf("у PE файлі відсутні секції")
	}

	var largestSection *SectionData

	for i := range sections {
		// Шукаємо тільки дійсні каверни
		if sections[i].CaveSize > 0 {
			if largestSection == nil || sections[i].CaveSize > largestSection.CaveSize {
				largestSection = &sections[i]
			}
		}
	}

	if largestSection == nil {
		return nil, fmt.Errorf("підходящих каверн (Slack Space) не знайдено")
	}

	return largestSection, nil
}

func (inj *Injector) WritePayload(caveOffset uint32, payload []byte) error {
	if inj.peFile != nil {
		_ = inj.peFile.Close()
		inj.peFile = nil
	}

	file, err := os.OpenFile(inj.filePath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("помилка відкриття файлу на запис: %w", err)
	}
	defer file.Close()

	_, err = file.Seek(int64(caveOffset), 0)
	if err != nil {
		return fmt.Errorf("помилка позиціонування Seek: %w", err)
	}

	written, err := file.Write(payload)
	if err != nil {
		return fmt.Errorf("помилка запису даних: %w", err)
	}

	if written != len(payload) {
		return fmt.Errorf("записано частково: %d з %d байт", written, len(payload))
	}

	return file.Sync()
}

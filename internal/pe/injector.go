package pe

import (
	"debug/pe"
	"fmt"
	"io"
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
	if inj.peFile == nil {
		peFile, err := pe.Open(inj.filePath)
		if err != nil {
			return nil, fmt.Errorf("помилка повторного відкриття PE файлу: %w", err)
		}
		inj.peFile = peFile
	}

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

// GetSmallerCavern шукає найменшу придатну каверну.
// Приймає ignoreOffset, щоб уникнути вибору тієї ж каверни, що й для payload.
// Якщо обмежень немає, передавай ignoreOffset = 0.
func (inj *Injector) GetSmallerCavern(ignoreOffset uint32) (*SectionData, error) {

	if inj.peFile == nil {
		peFile, err := pe.Open(inj.filePath)
		if err != nil {
			return nil, fmt.Errorf("помилка повторного відкриття PE файлу: %w", err)
		}
		inj.peFile = peFile
	}

	sections, err := inj.GetSectionDebugInfo()
	if err != nil {
		return nil, fmt.Errorf("виникла помилка отримання секцій: %w", err)
	}

	if len(sections) == 0 {
		return nil, fmt.Errorf("у PE файлі відсутні секції")
	}

	var smallestSection *SectionData

	for i := range sections {
		// Перевіряємо, що каверна дісна і не збігається з проігнорованою
		if sections[i].CaveSize > 0 && sections[i].CaveOffset != ignoreOffset {
			if smallestSection == nil || sections[i].CaveSize < smallestSection.CaveSize {
				smallestSection = &sections[i]
			}
		}
	}

	if smallestSection == nil {
		return nil, fmt.Errorf("підходящої окремої каверни не знайдено")
	}

	return smallestSection, nil
}

func (inj *Injector) ReadPayload(caveOffset uint32, size int) ([]byte, error) {
	// 1. Якщо peFile відкритий, закриваємо його, щоб уникнути конфліктів блокування
	if inj.peFile != nil {
		_ = inj.peFile.Close()
		inj.peFile = nil
	}

	// 2. Відкриваємо файл у режимі читання (os.O_RDONLY)
	file, err := os.Open(inj.filePath)
	if err != nil {
		return nil, fmt.Errorf("помилка відкриття файлу для читання: %w", err)
	}
	defer file.Close()

	// 3. Ставимо курсор на початок каверни
	_, err = file.Seek(int64(caveOffset), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("помилка позиціонування Seek: %w", err)
	}

	// 4. Створюємо буфер потрібного розміру та вичитуємо байти
	payload := make([]byte, size)
	_, err = io.ReadFull(file, payload)
	if err != nil {
		return nil, fmt.Errorf("помилка вичитання байтів: %w", err)
	}

	return payload, nil
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

// ExpandSectionRawSize розширює фізичний розмір секції на потрібну кількість байтів
func (inj *Injector) ExpandSectionRawSize(secName string, neededSize int) error {
	if inj.peFile != nil {
		_ = inj.peFile.Close()
		inj.peFile = nil
	}

	// 1. Відкриваємо файл у режимі читання/запису
	file, err := os.OpenFile(inj.filePath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("помилка відкриття файлу для розширення: %w", err)
	}
	defer file.Close()

	// 2. Зчитуємо PE-заголовок за допомогою stdlib debug/pe
	peFile, err := pe.Open(inj.filePath)
	if err != nil {
		return fmt.Errorf("помилка повторного читання заголовків: %w", err)
	}
	defer peFile.Close()

	var targetSec *pe.Section
	for _, sec := range peFile.Sections {
		if sec.Name == secName {
			targetSec = sec
			break
		}
	}

	if targetSec == nil {
		return fmt.Errorf("секцію %s не знайдено", secName)
	}

	// 3. Розраховуємо нове значення SizeOfRawData з урахуванням FileAlignment
	// Для стандартних PE-файлів FileAlignment зазвичай дорівнює 0x200 (512 байт)
	var fileAlign uint32 = 0x200
	newVirtualSize := targetSec.VirtualSize + uint32(neededSize)

	// Вирівнюємо новий розмір
	newSizeOfRawData := ((newVirtualSize + fileAlign - 1) / fileAlign) * fileAlign

	// 4. Дописуємо нульові байти в кінець файлу для збільшення розміру
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("помилка позиціонування у кінець файлу: %w", err)
	}

	padding := make([]byte, newSizeOfRawData-targetSec.Size)
	if _, err := file.Write(padding); err != nil {
		return fmt.Errorf("помилка запису padding-байтів: %w", err)
	}

	return file.Sync()
}

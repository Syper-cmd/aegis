package tests

import (
	"aegis/internal/pe"
	"testing"
)

func TestGetDebugData(t *testing.T) {
	testInjector, err := pe.New("notepad.exe")
	if err != nil {
		t.Fatalf("Виникла помилка: %v", err)
	}

	sectionsDebugInfo, err := testInjector.GetSectionDebugInfo()

	if err != nil {
		t.Fatalf("Виникла помилка: %v", err)
	}

	for _, secData := range sectionsDebugInfo {
		t.Logf("Name: %s\nVirtualSize: %d\nPhysSize: %d\nOffset: %d\nCavern: %d\n", secData.Name, secData.VirtualSize, secData.PhysSize, secData.Offset, secData.CaveSize)
	}
}

func TestGetLargestCavern(t *testing.T) {
	testInjector, err := pe.New("notepad.exe")

	if err != nil {
		t.Fatalf("Виникла помилка при створенні інжектора: %v", err)
	}

	largestCavernSec, err := testInjector.GetLargestCavern()

	if err != nil {
		t.Fatalf("Помилка при пошуку найбільшої каверни: %v", err)
	}

	t.Logf("Name: %s\nCavernSize: %d", largestCavernSec.Name, largestCavernSec.CaveSize)
}

func TestReadWritePayload(t *testing.T) {
	testInjector, err := pe.New("notepad.exe")

	if err != nil {
		t.Fatalf("Помилка при створенні інжектора: %v", err)
	}

	cave, err := testInjector.GetLargestCavern()

	if err != nil {
		t.Fatalf("Помилка при отриманні каверни: %v", err)
	}

	originalData := []byte("ТостоваяData123")

	err = testInjector.WritePayload(cave.CaveOffset, originalData)

	if err != nil {
		t.Fatalf("Помилка запису: %v", err)
	}

	extractedData, err := testInjector.ReadPayload(cave.CaveOffset, len(originalData))

	if err != nil {
		t.Fatalf("Помилка читання: %v", err)
	}

	t.Logf("Зчитанно: %s", string(extractedData))

	if string(extractedData) != string(originalData) {
		t.Fatalf("ПОМИЛКА! Зчитанна строка та строка-перевірка не зпівпадають!")
	}
}

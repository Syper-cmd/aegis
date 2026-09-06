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

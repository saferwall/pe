package pe

import (
	"os"
	"testing"
)

func Test_ParseIcon(t *testing.T) {
	file, err := New(os.Getenv("PE_FILE"), &Options{})
	if err != nil {
		t.Errorf("open file failed, err %v", err)
		return
	}

	err = file.Parse()
	if err != nil {
		t.Errorf("parse file failed, err %v", err)
		return
	}

	iconBytes, err := file.ParsePngIcon()
	if err != nil {
		t.Errorf("parse icon failed, err %v", err)
		return
	}

	os.WriteFile("test.png", iconBytes, 0644)

	t.Logf("length %d", len(iconBytes))
}

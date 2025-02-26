package pe

import (
	"bytes"
	"os"
	"testing"
)

func Test_ParseIcon(t *testing.T) {
	file, err := New(os.Getenv("PE_FILE"), &Options{})
	if err != nil {
		t.Errorf("open file failed, err %v", err)
		return
	}

	defer func() {
		_ = file.Close()
	}()

	err = file.Parse()
	if err != nil {
		t.Errorf("parse file failed, err %v", err)
		return
	}

	data, err := file.ParseIconToPng()
	if err != nil {
		t.Errorf("parse file failed, err %v", err)
		return
	}

	_ = os.WriteFile("test.png", data, 0644)
}

func TestBIPToPNGWithFile(t *testing.T) {
	// 读取测试文件
	bipData, err := os.ReadFile("temp.bip")
	if err != nil {
		t.Fatalf("fail to read bip file: %v", err)
	}

	// 验证BIP文件头
	if !bytes.HasPrefix(bipData, []byte{0x28, 0x00, 0x00, 0x00}) {
		t.Fatal("invalid bip header")
	}

	// 设置测试参数
	const (
		outputFile = "temp_test.png"
	)

	// 执行转换
	if data, err := BIPToPNG(bipData); err != nil {
		t.Fatalf("convert bip to png failed: %v", err)
	} else {
		_ = os.WriteFile(outputFile, data, 0644)
	}
}

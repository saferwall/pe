// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"io/ioutil"
	"os"
	"testing"
)

var peTests = []struct {
	in  string
	out error
}{
	{getAbsoluteFilePath("test/putty.exe"), nil},
}

func TestParse(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("Parse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestParseOmitDirectories(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{OmitSecurityDirectory: true})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("Parse(%s) got %v, want %v", tt.in, got, tt.out)
			}
			// Should expect an empty certificate
			if file.Certificates.Raw != nil {
				t.Errorf("Parse(%s) expected empty certificate", tt.in)
			}
		})
	}
}

func TestNewBytes(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			data, _ := ioutil.ReadFile(tt.in)
			file, err := NewBytes(data, &Options{})
			if err != nil {
				t.Fatalf("NewBytes(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("Parse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestChecksum(t *testing.T) {

	tests := []struct {
		in  string
		out uint32
	}{
		// file is DWORD aligned.
		{getAbsoluteFilePath("test/putty.exe"),
			0x00122C22},
		// file is not DWORD aligned and needs paddings.
		{getAbsoluteFilePath("test/010001e68577ef704792448ff474d22c6545167231982447c568e55041169ef0"),
			0x0006D558},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Checksum()
			if got != tt.out {
				t.Errorf("Checksum(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

func TestCanParseWithHandleAndClose(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := os.Open(tt.in)
			if err != nil {
				t.Fatalf("Open file(%s) failed", tt.in)
			}
			pefile, err := NewFile(file, &Options{})
			if err != nil {
				t.Fatalf("NewFile (%s) failed", tt.in)
			}
			err = pefile.Parse()
			if err != nil {
				t.Fatalf("Parse (%s) failed", tt.in)
			}
			err = pefile.Unmap()
			if err != nil {
				t.Fatalf("Unmap (%s) failed", tt.in)
			}
			const len = 2
			header := [len]byte{}
			n, err := file.ReadAt(header[:], 0)
			if err != nil {
				t.Fatalf("Failed to read after unmap (%s)", tt.in)
			}
			if n != len {
				t.Fatalf("Failed to read data (%s)", tt.in)
			}
			err = file.Close()
			if err != nil {
				t.Fatalf("Failed to close file (%s)", tt.in)
			}
		})
	}
}

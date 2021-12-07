// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"runtime"
	"testing"
)

func getAbsoluteFilePath(testfile string) string {
	_, p, _, _ := runtime.Caller(0)
	return path.Join(filepath.Dir(p), testfile)
}

var peTests = []struct {
	in  string
	out error
}{
	{getAbsoluteFilePath("test/putty"), nil},
}

func TestParse(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("TestParse(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("TestParse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestNewBytes(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			data, _ := ioutil.ReadFile(tt.in)
			file, err := NewBytes(data, nil)
			if err != nil {
				t.Errorf("TestNewBytes(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("TestNewBytes(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestAuthentihash(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty"),
			"8be7d65593b0fff2e8b29004640261b8a0d4fcc651a14cd0b8b702b7928f8ee0"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("TestAuthentihash(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("TestAuthentihash(%s) failed, reason: %v", tt.in, err)
				return
			}

			hash := file.Authentihash()
			got := fmt.Sprintf("%x", hash)
			if string(got) != tt.out {
				t.Errorf("TestAuthentihash(%s) got %v, want %v", tt.in, got, tt.out)
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
		{getAbsoluteFilePath("test/putty"),
			0x00122C22},
		// file is not DWORD aligned and needs paddings.
		{getAbsoluteFilePath("test/010001e68577ef704792448ff474d22c6545167231982447c568e55041169ef0"),
			0x0006D558},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("TestChecksum(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("TestChecksum(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := file.Checksum()
			if got != tt.out {
				t.Errorf("TestChecksum(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

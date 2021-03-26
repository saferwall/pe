// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
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

var tridtests = []struct {
	in  string
	out error
}{
	{getAbsoluteFilePath("test/putty"), nil},
}

func TestParse(t *testing.T) {
	for _, tt := range tridtests {
		t.Run(tt.in, func(t *testing.T) {
			filePath := tt.in
			pe, err := New(filePath, nil)
			if err != nil {
				t.Errorf("TestParse(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := pe.Parse()
			if got != nil {
				t.Errorf("TestParse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestNewBytes(t *testing.T) {
	for _, tt := range tridtests {
		t.Run(tt.in, func(t *testing.T) {
			filePath := tt.in
			data, err := ioutil.ReadFile(filePath)
			pe, err := NewBytes(data, nil)
			if err != nil {
				t.Errorf("TestParse(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := pe.Parse()
			if got != nil {
				t.Errorf("TestParse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

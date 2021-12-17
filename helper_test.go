// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"testing"
)

func TestIsEXE(t *testing.T) {

	tests := []struct {
		in  string
		out bool
	}{
		{getAbsoluteFilePath("test/liblzo2-2"), false},
		{getAbsoluteFilePath("test/putty"), true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("New(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("Parse(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := file.IsEXE()
			if got != tt.out {
				t.Errorf("IsEXE(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

func TestIsDLL(t *testing.T) {

	tests := []struct {
		in  string
		out bool
	}{
		{getAbsoluteFilePath("test/liblzo2-2"), true},
		{getAbsoluteFilePath("test/putty"), false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("New(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("Parse(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := file.IsDLL()
			if got != tt.out {
				t.Errorf("IsDLL(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

func TestIsDriver(t *testing.T) {

	tests := []struct {
		in  string
		out bool
	}{
		{getAbsoluteFilePath("test/liblzo2-2"), false},
		{getAbsoluteFilePath("test/WdBoot"), true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("New(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("Parse(%s) failed, reason: %v", tt.in, err)
				return
			}

			got := file.IsDriver()
			if got != tt.out {
				t.Errorf("IsDriver(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

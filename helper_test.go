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
		{getAbsoluteFilePath("test/liblzo2-2.dll"), false},
		{getAbsoluteFilePath("test/putty.exe"), true},
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
		{getAbsoluteFilePath("test/liblzo2-2.dll"), true},
		{getAbsoluteFilePath("test/putty.exe"), false},
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
		{getAbsoluteFilePath("test/liblzo2-2.dll"), false},
		{getAbsoluteFilePath("test/WdBoot.sys"), true},
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

			got := file.IsDriver()
			if got != tt.out {
				t.Errorf("IsDriver(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

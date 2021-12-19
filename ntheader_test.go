// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"sort"
	"testing"
)

func TestPrettyMachineType(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty.exe"), "x64"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			prettyMachineType := file.PrettyMachineType()
			if prettyMachineType != tt.out {
				t.Errorf("pretty machine type assertion failed, got %v, want %v",
					prettyMachineType, tt.out)
			}
		})
	}
}

func TestSubsystem(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty.exe"), "Windows GUI"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			prettySubsystem := file.PrettySubsystem()
			if prettySubsystem != tt.out {
				t.Errorf("pretty subsystem type assertion failed, got %v, want %v",
				prettySubsystem, tt.out)
			}
		})
	}
}

func TestPrettyDllCharacteristics(t *testing.T) {

	tests := []struct {
		in  string
		out []string
	}{
		{getAbsoluteFilePath("test/putty.exe"), []string{
			"DynamicBase", "HighEntropyVA", "NXCompact", "TerminalServiceAware"}},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			dllCharacteristics := file.PrettyDllCharacteristics()
			sort.Strings(dllCharacteristics)
			if !reflect.DeepEqual(dllCharacteristics, tt.out) {
				t.Errorf("pretty dll characteristics type assertion failed, got %v, want %v",
					dllCharacteristics, tt.out)
			}

		})
	}
}

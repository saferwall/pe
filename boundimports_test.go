// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestBoundImportEntry struct {
	entryCount     int
	entryIndex     int
	entry          BoundImportDescriptorData
	errOutOfBounds error
}

func TestBoundImportDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestBoundImportEntry
	}{
		{
			getAbsoluteFilePath("test/mfc40u.dll"),
			TestBoundImportEntry{
				entryCount: 4,
				entryIndex: 0,
				entry: BoundImportDescriptorData{
					Struct: ImageBoundImportDescriptor{
						TimeDateStamp:               0x31CB50F3,
						OffsetModuleName:            0x38,
						NumberOfModuleForwarderRefs: 0x1,
					},
					Name: "MSVCRT40.dll",
					ForwardedRefs: []BoundForwardedRefData{
						{
							Struct: ImageBoundForwardedRef{
								TimeDateStamp:    0x3B7DFE0E,
								OffsetModuleName: 0x45,
								Reserved:         0x0,
							},
							Name: "msvcrt.DLL",
						},
					},
				},
				errOutOfBounds: nil,
			},
		},
		{
			// fake bound imports directory
			getAbsoluteFilePath("test/0044e1870806c048a7558082d4482d1650dcd3ea73152ed2218a554983130721"),
			TestBoundImportEntry{
				errOutOfBounds: ErrOutsideBoundary,
			},
		},
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

			var va, size uint32

			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryBoundImport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryBoundImport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseBoundImportDirectory(va, size)
			if err != tt.out.errOutOfBounds {
				t.Fatalf("parseBoundImportDirectory(%s) failed, reason: %v", tt.in, err)
			}
			got := file.BoundImports
			if len(got) != tt.out.entryCount {
				t.Errorf("bound imports entry count assertion failed, got %v, want %v", len(got), tt.out.entryCount)
			}

			if len(file.BoundImports) > 0 {
				boundImportEntry := file.BoundImports[tt.out.entryIndex]
				if !reflect.DeepEqual(boundImportEntry, tt.out.entry) {
					t.Errorf("bound import entry assertion failed, got %v, want %v", boundImportEntry, tt.out.entry)
				}
			}
		})
	}
}

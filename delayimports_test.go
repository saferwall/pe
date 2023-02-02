// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestDelayImportEntry struct {
	entryCount int
	entryIndex int
	entry      DelayImport
}

func TestDelayImportDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestDelayImportEntry
	}{
		{
			getAbsoluteFilePath("test/000049925c578e5a0883e7d1a8257c1a44feab8f7d9972ace8d0e3fb96612a4c"),
			TestDelayImportEntry{
				entryCount: 4,
				entryIndex: 0,
				entry: DelayImport{
					Offset: 0x5F7C00,
					Name:   "kernel32.dll",
					Functions: []ImportFunction{
						{
							Name:               "GetLogicalProcessorInformation",
							Hint:               0x0,
							ByOrdinal:          false,
							OriginalThunkValue: 0x601192,
							ThunkValue:         0xF04E60,
							ThunkRVA:           0x6010B4,
							OriginalThunkRVA:   0x6010F0,
						},
					},
					Descriptor: ImageDelayImportDescriptor{
						Attributes:                 0x1,
						Name:                       0x601184,
						ModuleHandleRVA:            0x6010A0,
						ImportAddressTableRVA:      0x6010B4,
						ImportNameTableRVA:         0x6010F0,
						BoundImportAddressTableRVA: 0x60112C,
						UnloadInformationTableRVA:  0x601158,
						TimeDateStamp:              0x0,
					},
				},
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryDelayImport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryDelayImport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseDelayImportDirectory(va, size)
			if err != nil {
				t.Fatalf("parseDelayImportDirectory(%s) failed, reason: %v", tt.in, err)
			}
			got := file.DelayImports
			if len(got) != tt.out.entryCount {
				t.Errorf("delay imports entry count assertion failed, got %v, want %v",
					len(got), tt.out.entryCount)
			}

			if len(file.DelayImports) > 0 {
				delayImportEntry := file.DelayImports[tt.out.entryIndex]
				if !reflect.DeepEqual(delayImportEntry, tt.out.entry) {
					t.Errorf("delay import entry assertion failed, got %v, want %v",
						delayImportEntry, tt.out.entry)
				}
			}

		})
	}
}

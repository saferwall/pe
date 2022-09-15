// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestExport struct {
	entryCount int
	entryIndex int
	name       string
	imgExpDir  ImageExportDirectory
	expFunc    ExportFunction
}

func TestExportDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestExport
	}{
		{
			getAbsoluteFilePath("test/kernel32.dll"),
			TestExport{
				entryCount: 1633,
				entryIndex: 0,
				name:       "KERNEL32.dll",
				imgExpDir: ImageExportDirectory{
					Characteristics:       0x0,
					TimeDateStamp:         0x38B369C4,
					MajorVersion:          0x0,
					MinorVersion:          0x0,
					Name:                  0x0009E1D2,
					Base:                  0x1,
					NumberOfFunctions:     0x661,
					NumberOfNames:         0x661,
					AddressOfFunctions:    0x0009A208,
					AddressOfNames:        0x0009BB8C,
					AddressOfNameOrdinals: 0x0009D510,
				},
				expFunc: ExportFunction{
					Ordinal:      0x1,
					FunctionRVA:  0x0009E1F7,
					NameOrdinal:  0x0,
					NameRVA:      0x0009E1DF,
					Name:         "AcquireSRWLockExclusive",
					Forwarder:    "NTDLL.RtlAcquireSRWLockExclusive",
					ForwarderRVA: 0x9CBF7,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryExport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryExport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseExportDirectory(va, size)
			if err != nil {
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v", tt.in, err)
			}
			got := file.Export
			if len(got.Functions) != tt.out.entryCount {
				t.Errorf("export functions count assertion failed, got %v, want %v",
					len(got.Functions), tt.out.entryCount)
			}

			imgExpDir := file.Export.Struct
			if !reflect.DeepEqual(imgExpDir, tt.out.imgExpDir) {
				t.Errorf("image export directory assertion failed, got %v, want %v",
					imgExpDir, tt.out.imgExpDir)
			}

			if len(file.Export.Functions) > 0 {
				expFunc := file.Export.Functions[tt.out.entryIndex]
				if !reflect.DeepEqual(expFunc, tt.out.expFunc) {
					t.Errorf("export entry assertion failed, got %v, want %v", expFunc, tt.out.expFunc)
				}
			}
		})
	}
}

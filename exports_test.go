// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
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
					TimeDateStamp:         0x38B369C4,
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
					NameRVA:      0x0009E1DF,
					Name:         "AcquireSRWLockExclusive",
					Forwarder:    "NTDLL.RtlAcquireSRWLockExclusive",
					ForwarderRVA: 0x9CBF7,
				},
			},
		},
		{
			getAbsoluteFilePath("test/mfc140u.dll"),
			TestExport{
				entryCount: 14103,
				entryIndex: 0,
				name:       "KERNEL32.dll",
				imgExpDir: ImageExportDirectory{
					TimeDateStamp:      0x5b8f7bca,
					Name:               0x3e2e0c,
					Base:               0x100,
					NumberOfFunctions:  0x371d,
					AddressOfFunctions: 0x3d5198,
				},
				expFunc: ExportFunction{
					Ordinal:     0x100,
					FunctionRVA: 0x275fa0,
				},
			},
		},
		{
			getAbsoluteFilePath("test/0b1d3d3664915577ab9a32188d29bbf3542b86c7b9ce333e245496c3018819f1"),
			TestExport{
				entryCount: 7728638,
				entryIndex: 0,
				name:       "",
				imgExpDir: ImageExportDirectory{
					Characteristics:       0xac0000,
					TimeDateStamp:         0xac0000,
					MinorVersion:          0xac,
					Name:                  0xac0000,
					Base:                  0xac0000,
					NumberOfFunctions:     0xac0000,
					NumberOfNames:         0xac0000,
					AddressOfFunctions:    0xac0000,
					AddressOfNames:        0xac0000,
					AddressOfNameOrdinals: 0xac0000,
				},
				expFunc: ExportFunction{
					Ordinal:     0xac0000,
					FunctionRVA: 0xac0000,
					NameRVA:     0xac0000,
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

			export := file.Export
			if len(export.Functions) != tt.out.entryCount {
				t.Fatalf("export functions count assertion failed, got %v, want %v",
					len(export.Functions), tt.out.entryCount)
			}

			imgExpDir := export.Struct
			if imgExpDir != tt.out.imgExpDir {
				t.Fatalf("image export directory assertion failed, got %v, want %v",
					imgExpDir, tt.out.imgExpDir)
			}

			if len(export.Functions) > 0 {
				expFunc := export.Functions[tt.out.entryIndex]
				if expFunc != tt.out.expFunc {
					t.Fatalf("export entry assertion failed, got %v, want %v", expFunc, tt.out.expFunc)
				}
			}
		})
	}
}

// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestImportEntry struct {
	entryCount int
	entryIndex int
	entry      Import
}

func TestImportDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestImportEntry
	}{
		{
			getAbsoluteFilePath("test/kernel32.dll"),
			TestImportEntry{
				entryCount: 96,
				entryIndex: 34,
				entry: Import{
					Offset: 0xa6d94,
					Name:   "api-ms-win-core-namedpipe-l1-2-1.dll",
					Descriptor: ImageImportDescriptor{
						OriginalFirstThunk: 0xa9a38,
						TimeDateStamp:      0x0,
						ForwarderChain:     0x0,
						Name:               0xaeeb8,
						FirstThunk:         0x82978,
					},
					Functions: []ImportFunction{
						{
							Name:               "GetNamedPipeHandleStateW",
							Hint:               0x6,
							ByOrdinal:          false,
							Ordinal:            0x0,
							OriginalThunkValue: 0xaee00,
							ThunkValue:         0xaee00,
							ThunkRVA:           0x82978,
							OriginalThunkRVA:   0xa9a38,
						},
					},
				},
			},
		},
		{
			getAbsoluteFilePath("test/impbyord.exe"),
			TestImportEntry{
				entryCount: 2,
				entryIndex: 1,
				entry: Import{
					Offset: 0x284,
					Name:   "impbyord.exe",
					Descriptor: ImageImportDescriptor{
						OriginalFirstThunk: 0x10b4,
						TimeDateStamp:      0x0,
						ForwarderChain:     0x0,
						Name:               0x10d0,
						FirstThunk:         0x1058,
					},
					Functions: []ImportFunction{
						{
							Name:               "#35",
							Hint:               0x0,
							ByOrdinal:          true,
							Ordinal:            0x23,
							OriginalThunkValue: 0x80000023,
							ThunkValue:         0x10b4,
							ThunkRVA:           0x1058,
							OriginalThunkRVA:   0x10b4,
						},
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryImport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryImport]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseImportDirectory(va, size)
			if err != nil {
				t.Fatalf("parseImportDirectory(%s) failed, reason: %v", tt.in, err)
			}
			got := file.Imports
			if len(got) != tt.out.entryCount {
				t.Errorf("imports entry count assertion failed, got %v, want %v", len(got), tt.out.entryCount)
			}

			impFunc := file.Imports[tt.out.entryIndex]
			if !reflect.DeepEqual(impFunc, tt.out.entry) {
				t.Errorf("import function entry assertion failed, got %v, want %v", impFunc, tt.out.entry)
			}
		})
	}
}

func TestImpHash(t *testing.T) {
	for _, tt := range []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty.exe"), "2e3215acc61253e5fa73a840384e9720"},
		{getAbsoluteFilePath("test/01008963d32f5cc17b64c31446386ee5b36a7eab6761df87a2989ba9394d8f3d"), "431cb9bbc479c64cb0d873043f4de547"},
		{getAbsoluteFilePath("test/0103daa751660333b7ae5f098795df58f07e3031563e042d2eb415bffa71fe7a"), "8b58a51c1fff9c4a944265c1fe0fab74"},
		{getAbsoluteFilePath("test/0585495341e0ffaae1734acb78708ff55cd3612d844672d37226ef63d12652d0"), "e4290fa6afc89d56616f34ebbd0b1f2c"},
	} {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			if err := file.Parse(); err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}
			impHash, err := file.ImpHash()
			if err != nil {
				t.Fatalf("ImpHash(%s) failed, reason: %v", tt.in, err)
			}
			if impHash != tt.out {
				t.Errorf("ImpHash(%s) got %v, want %v", tt.in, impHash, tt.out)
			}
		})
	}
}

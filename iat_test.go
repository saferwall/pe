// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestIATEntry struct {
	entryCount int
	entryIndex int
	entry      IATEntry
}

func TestIATDirectory(t *testing.T) {
	tests := []struct {
		in  string
		out TestIATEntry
	}{
		{
			// PE32 binary: 32-bit IAT entries (uint32 values, 4-byte stride).
			getAbsoluteFilePath("test/arp.dll"),
			TestIATEntry{
				entryCount: 29,
				entryIndex: 0,
				entry: IATEntry{
					Index:   0,
					Rva:     0x8000,
					Value:   uint32(28236),
					Meaning: "COREDLL.dll!WaitForSingleObject",
				},
			},
		},
		{
			// PE32+ binary: 64-bit IAT entries (uint64 values, 8-byte stride).
			// Checks first entry — verifies the RVA lookup is not off by one stride.
			getAbsoluteFilePath("test/putty.exe"),
			TestIATEntry{
				entryCount: 332,
				entryIndex: 0,
				entry: IATEntry{
					Index:   0,
					Rva:     0xc5d00,
					Value:   uint64(812896),
					Meaning: "GDI32.dll!CreateBitmap",
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryIAT]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryIAT]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			// parseIATDirectory needs imports populated for Meaning lookups.
			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				impDir := oh64.DataDirectory[ImageDirectoryEntryImport]
				_ = file.parseImportDirectory(impDir.VirtualAddress, impDir.Size)
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				impDir := oh32.DataDirectory[ImageDirectoryEntryImport]
				_ = file.parseImportDirectory(impDir.VirtualAddress, impDir.Size)
			}

			err = file.parseIATDirectory(va, size)
			if err != nil {
				t.Fatalf("parseIATDirectory(%s) failed, reason: %v", tt.in, err)
			}

			if !file.HasIAT {
				t.Errorf("HasIAT(%s) = false, want true", tt.in)
			}

			got := file.IAT
			if len(got) != tt.out.entryCount {
				t.Errorf("IAT entry count for %s: got %d, want %d", tt.in, len(got), tt.out.entryCount)
			}

			entry := got[tt.out.entryIndex]
			if !reflect.DeepEqual(entry, tt.out.entry) {
				t.Errorf("IAT[%d] for %s: got %+v, want %+v", tt.out.entryIndex, tt.in, entry, tt.out.entry)
			}
		})
	}
}

func TestIATDirectoryOmit(t *testing.T) {
	file, err := New(getAbsoluteFilePath("test/putty.exe"), &Options{OmitIATDirectory: true})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if err := file.Parse(); err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if file.HasIAT {
		t.Error("HasIAT = true with OmitIATDirectory, want false")
	}
	if len(file.IAT) != 0 {
		t.Errorf("IAT len = %d with OmitIATDirectory, want 0", len(file.IAT))
	}
}

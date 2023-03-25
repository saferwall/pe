// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"testing"
)

func TestParseRelocDirectoryData(t *testing.T) {

	type TestRelocData struct {
		imgBaseRelocation ImageBaseRelocation
		relocEntriesCount int
		relocDataIndex    int
	}

	tests := []struct {
		in  string
		out TestRelocData
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestRelocData{
				imgBaseRelocation: ImageBaseRelocation{
					VirtualAddress: 0xd8000, SizeOfBlock: 0xc},
				relocEntriesCount: 18,
				relocDataIndex:    17,
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
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryBaseReloc]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryBaseReloc]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseRelocDirectory(va, size)
			if err != nil {
				t.Fatalf("parseRelocDirectory(%s) failed, reason: %v", tt.in, err)
			}
			relocs := file.Relocations
			if len(relocs) != tt.out.relocEntriesCount {
				t.Errorf("relocations entries count assertion failed, got %v, want %v",
					len(relocs), tt.out.relocEntriesCount)
			}

			imgBaseRelocation := relocs[tt.out.relocDataIndex].Data
			if imgBaseRelocation != tt.out.imgBaseRelocation {
				t.Errorf("reloc data assertion failed, got %v, want %v",
					imgBaseRelocation, tt.out.imgBaseRelocation)
			}
		})
	}
}

func TestParseRelocDirectoryEntry(t *testing.T) {

	type TestRelocEntry struct {
		imgBaseRelocationEntry ImageBaseRelocationEntry
		relocEntriesCount      int
		relocDataIndex         int
		relocEntryIndex        int
		relocTypeMeaning       string
	}

	tests := []struct {
		in  string
		out TestRelocEntry
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestRelocEntry{
				imgBaseRelocationEntry: ImageBaseRelocationEntry{
					Data:   0xab00,
					Offset: 0xb00,
					Type:   0xa,
				},
				relocDataIndex:    0x1,
				relocEntriesCount: 154,
				relocEntryIndex:   17,
				relocTypeMeaning:  "DIR64",
			},
		},
		{
			getAbsoluteFilePath("test/arp.dll"),
			TestRelocEntry{
				imgBaseRelocationEntry: ImageBaseRelocationEntry{
					Data:   0x8004,
					Offset: 0x4,
					Type:   0x8,
				},
				relocDataIndex:    3,
				relocEntriesCount: 204,
				relocEntryIndex:   1,
				relocTypeMeaning:  "RISC-V Low12s",
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
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryBaseReloc]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryBaseReloc]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseRelocDirectory(va, size)
			if err != nil {
				t.Fatalf("parseRelocDirectory(%s) failed, reason: %v", tt.in, err)
			}

			reloc := file.Relocations[tt.out.relocDataIndex]
			if len(reloc.Entries) != tt.out.relocEntriesCount {
				t.Errorf("relocations entries count assertion failed, got %v, want %v",
					len(reloc.Entries), tt.out.relocEntriesCount)
			}

			relocEntry := reloc.Entries[tt.out.relocEntryIndex]
			if relocEntry != tt.out.imgBaseRelocationEntry {
				t.Errorf("reloc image base relocation entry assertion failed, got %v, want %v",
					relocEntry, tt.out.imgBaseRelocationEntry)
			}

			relocType := relocEntry.Type.String(file)
			if relocType != tt.out.relocTypeMeaning {
				t.Errorf("pretty reloc type assertion failed, got %v, want %v", relocType,
					tt.out.relocTypeMeaning)
			}

		})
	}
}

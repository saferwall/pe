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

// TestParseRelocDirectoryZeroSizeOfBlock exercises the end-of-table sentinel
// (VirtualAddress=0, SizeOfBlock=0). Before the fix, the sentinel was handed
// to parseRelocations unchanged; SizeOfBlock - relocSize underflowed (uint32)
// and the parser synthesised millions of phantom entries from bytes past the
// real reloc table, ballooning the marshalled output to ~154 MB.
//
// The sample below is a real PE with 14 legitimate relocation blocks followed
// by the {0,0} sentinel. We assert that:
//   - the sentinel block is NOT appended to pe.Relocations
//   - the total number of parsed entries stays bounded (3558 real entries)
//   - the last real block matches the expected header
func TestParseRelocDirectoryZeroSizeOfBlock(t *testing.T) {
	in := getAbsoluteFilePath(
		"test/05df99cc2e77a59aa3443cae13325af553271bddaeedff3c08bf4f6995bbc62d")

	ops := Options{Fast: true}
	file, err := New(in, &ops)
	if err != nil {
		t.Fatalf("New(%s) failed, reason: %v", in, err)
	}
	if err := file.Parse(); err != nil {
		t.Fatalf("Parse(%s) failed, reason: %v", in, err)
	}

	var va, size uint32
	switch file.Is64 {
	case true:
		dirEntry := file.NtHeader.OptionalHeader.(ImageOptionalHeader64).
			DataDirectory[ImageDirectoryEntryBaseReloc]
		va, size = dirEntry.VirtualAddress, dirEntry.Size
	case false:
		dirEntry := file.NtHeader.OptionalHeader.(ImageOptionalHeader32).
			DataDirectory[ImageDirectoryEntryBaseReloc]
		va, size = dirEntry.VirtualAddress, dirEntry.Size
	}

	if err := file.parseRelocDirectory(va, size); err != nil {
		t.Fatalf("parseRelocDirectory(%s) failed, reason: %v", in, err)
	}

	// Exactly 14 real blocks — the {0,0} sentinel must not be appended.
	if got, want := len(file.Relocations), 14; got != want {
		t.Fatalf("relocation block count: got %d, want %d", got, want)
	}

	// No block should carry a zero SizeOfBlock — if one does, the sentinel
	// slipped through.
	for i, r := range file.Relocations {
		if r.Data.SizeOfBlock == 0 {
			t.Errorf("block %d has SizeOfBlock=0 (sentinel leaked into result)", i)
		}
	}

	// Total entries across all blocks must be bounded (pre-fix: 4,270,384).
	total := 0
	for _, r := range file.Relocations {
		total += len(r.Entries)
	}
	if total != 3558 {
		t.Errorf("total relocation entries: got %d, want 3558", total)
	}

	// The last legitimate block.
	last := file.Relocations[13]
	wantLast := ImageBaseRelocation{VirtualAddress: 0x466000, SizeOfBlock: 20}
	if last.Data != wantLast {
		t.Errorf("last block header: got %+v, want %+v", last.Data, wantLast)
	}
	if len(last.Entries) != 6 {
		t.Errorf("last block entry count: got %d, want 6", len(last.Entries))
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

// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestReloc struct {
	reloc            Relocation
	relocCount       int
	relocIndex       int
	relocTypeMeaning string
}

func TestParseRelocDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestReloc
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestReloc{
				reloc: Relocation{
					Data: ImageBaseRelocation{VirtualAddress: 0xd8000, SizeOfBlock: 0xc},
					Entries: []ImageBaseRelocationEntry{
						{Data: 0xa000, Offset: 0x0, Type: 0xa},
						{Data: 0xa008, Offset: 0x8, Type: 0xa},
					},
				},
				relocCount:       18,
				relocIndex:       17,
				relocTypeMeaning: "DIR64",
			},
		},
		{
			// fake exception directory
			getAbsoluteFilePath("test/01008963d32f5cc17b64c31446386ee5b36a7eab6761df87a2989ba9394d8f3d"),
			TestReloc{
				reloc: Relocation{
					Data: ImageBaseRelocation{VirtualAddress: 0x11000, SizeOfBlock: 0x10},
					Entries: []ImageBaseRelocationEntry{
						{Data: 0x3310, Offset: 0x310, Type: 0x3},
						{Data: 0x3320, Offset: 0x320, Type: 0x3},
						{Data: 0x3324, Offset: 0x324, Type: 0x3},
						{Data: 0x0, Offset: 0x0, Type: 0x0},
					},
				},
				relocCount:       9,
				relocIndex:       7,
				relocTypeMeaning: "HighLow",
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
			if len(relocs) != tt.out.relocCount {
				t.Errorf("Relocations count assertion failed, got %v, want %v",
					len(relocs), tt.out.relocCount)
			}

			reloc := relocs[tt.out.relocIndex]
			if !reflect.DeepEqual(reloc, tt.out.reloc) {
				t.Errorf("reloc assertion failed, got %v, want %v", reloc, tt.out.reloc)
			}

			prettyType := file.PrettyRelocTypeEntry(reloc.Entries[0].Type)
			if prettyType != tt.out.relocTypeMeaning {
				t.Errorf("pretty reloc type assertion failed, got %v, want %v", prettyType,
					tt.out.relocTypeMeaning)
			}

		})
	}
}

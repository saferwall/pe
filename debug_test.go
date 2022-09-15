// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestDebugEntry struct {
	debugEntry DebugEntry
}

type TestPOGO struct {
	imgDebugEntry ImageDebugDirectory
	entriesCount  int
	firstEntry    ImagePGOItem
	lastEntry     ImagePGOItem
}

type TestDebugIn struct {
	index      int
	filepath   string
	firstIndex int
	lastIndex  int
}

func TestDebugDirectoryCodeView(t *testing.T) {

	tests := []struct {
		in  TestDebugIn
		out TestDebugEntry
	}{
		{
			TestDebugIn{
				index:    0,
				filepath: getAbsoluteFilePath("test/kernel32.dll"),
			},
			TestDebugEntry{
				debugEntry: DebugEntry{
					Struct: ImageDebugDirectory{
						Characteristics:  0x0,
						TimeDateStamp:    0x38b369c4,
						MajorVersion:     0x0,
						MinorVersion:     0x0,
						Type:             0x2,
						SizeOfData:       0x25,
						AddressOfRawData: 0x932f0,
						PointerToRawData: 0x91cf0,
					},
					Info: CvInfoPDB70{
						CvSignature: 0x53445352,
						Signature: GUID{
							Data1: 0xdbe09e71,
							Data2: 0xb370,
							Data3: 0x9cb7,
							Data4: [8]byte{34, 197, 94, 85, 115, 250, 123, 225},
						},
						Age:         0x1,
						PDBFileName: "kernel32.pdb",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in.filepath, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in.filepath, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in.filepath, err)
			}

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in.filepath, err)
			}

			var va, size uint32

			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryDebug]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryDebug]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseDebugDirectory(va, size)
			if err != nil {
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v", tt.in.filepath, err)
			}

			debugEntry := file.Debugs[tt.in.index]
			if !reflect.DeepEqual(debugEntry, tt.out.debugEntry) {
				t.Errorf("debug entry assertion failed, got %v, want %v", debugEntry, tt.out.debugEntry)
			}
		})
	}
}

func TestDebugDirectoryREPRO(t *testing.T) {

	tests := []struct {
		in  TestDebugIn
		out TestDebugEntry
	}{

		{
			TestDebugIn{
				index:    2,
				filepath: getAbsoluteFilePath("test/kernel32.dll"),
			},
			TestDebugEntry{
				debugEntry: DebugEntry{
					Struct: ImageDebugDirectory{
						Characteristics:  0x0,
						TimeDateStamp:    0x38b369c4,
						MajorVersion:     0x0,
						MinorVersion:     0x0,
						Type:             0x10,
						SizeOfData:       0x24,
						AddressOfRawData: 0x9388c,
						PointerToRawData: 0x9228c,
					},
					Info: REPRO{
						Size: 0x20,
						Hash: []byte{113, 158, 224, 219, 112, 179, 183, 156, 34, 197, 94, 85, 115, 250, 123, 225, 130,
							247, 187, 89, 220, 154, 207, 99, 80, 113, 179, 171, 196, 105, 179, 56},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in.filepath, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in.filepath, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in.filepath, err)
			}

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in.filepath, err)
			}

			var va, size uint32

			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryDebug]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryDebug]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseDebugDirectory(va, size)
			if err != nil {
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v", tt.in.filepath, err)
			}

			debugEntry := file.Debugs[tt.in.index]
			if !reflect.DeepEqual(debugEntry, tt.out.debugEntry) {
				t.Errorf("debug entry assertion failed, got %v, want %v", debugEntry, tt.out.debugEntry)
			}
		})
	}
}

func TestDebugDirectoryPOGO(t *testing.T) {

	tests := []struct {
		in  TestDebugIn
		out TestPOGO
	}{
		{
			TestDebugIn{
				index:      1,
				filepath:   getAbsoluteFilePath("test/kernel32.dll"),
				firstIndex: 0,
				lastIndex:  62,
			},
			TestPOGO{
				imgDebugEntry: ImageDebugDirectory{
					Characteristics:  0x0,
					TimeDateStamp:    0x38b369c4,
					MajorVersion:     0x0,
					MinorVersion:     0x0,
					Type:             0xd,
					SizeOfData:       0x574,
					AddressOfRawData: 0x93318,
					PointerToRawData: 0x91d18,
				},
				entriesCount: 63,
				firstEntry: ImagePGOItem{
					Rva:  0x1000,
					Size: 0x280,
					Name:  ".text$lp00kernel32.dll!20_pri7",
				},
				lastEntry: ImagePGOItem{
					Rva:  0xbc0b0,
					Size: 0x470,
					Name:  ".rsrc$02",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in.filepath, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in.filepath, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in.filepath, err)
			}

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in.filepath, err)
			}

			var va, size uint32

			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryDebug]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryDebug]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseDebugDirectory(va, size)
			if err != nil {
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v", tt.in.filepath, err)
			}

			imgDebugEntry := file.Debugs[tt.in.index].Struct
			if !reflect.DeepEqual(imgDebugEntry, tt.out.imgDebugEntry) {
				t.Errorf("debug entry assertion failed, got %v, want %v", imgDebugEntry, tt.out.imgDebugEntry)
			}

			pogo := file.Debugs[tt.in.index].Info.(POGO).Entries[tt.in.firstIndex]
			if !reflect.DeepEqual(pogo, tt.out.firstEntry) {
				t.Errorf("debug pogo entry assertion failed, got %v, want %v", pogo, tt.out.firstEntry)
			}

			pogo = file.Debugs[tt.in.index].Info.(POGO).Entries[tt.in.lastIndex]
			if !reflect.DeepEqual(pogo, tt.out.lastEntry) {
				t.Errorf("debug pogo entry assertion failed, got %v, want %v", pogo, tt.out.lastEntry)
			}
		})
	}
}

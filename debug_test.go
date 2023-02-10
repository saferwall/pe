// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestDebugIn struct {
	filepath string
	index    int // debug entry index
}

func TestDebugDirectoryCodeView(t *testing.T) {

	type TestCodeView struct {
		debugType  string
		debugEntry DebugEntry
		signature  string
	}

	tests := []struct {
		in  TestDebugIn
		out TestCodeView
	}{
		{
			TestDebugIn{
				index:    0,
				filepath: getAbsoluteFilePath("test/kernel32.dll"),
			},
			TestCodeView{
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
					Info: CVInfoPDB70{
						CVSignature: 0x53445352,
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
				debugType: "CodeView",
				signature: "RSDS",
			},
		},
		{
			TestDebugIn{
				index:    0,
				filepath: getAbsoluteFilePath("test/01008963d32f5cc17b64c31446386ee5b36a7eab6761df87a2989ba9394d8f3d"),
			},
			TestCodeView{
				debugEntry: DebugEntry{
					Struct: ImageDebugDirectory{
						Characteristics:  0x0,
						TimeDateStamp:    0x3b7d84d4,
						MajorVersion:     0x0,
						MinorVersion:     0x0,
						Type:             0x2,
						SizeOfData:       0x1d,
						AddressOfRawData: 0x1cf4,
						PointerToRawData: 0x10f4,
					},
					Info: CVInfoPDB20{
						CVHeader: CVHeader{
							Signature: 0x3031424e,
							Offset:    0x0,
						},
						Signature:   0x3b7d84d4,
						Age:         0x1,
						PDBFileName: "routemon.pdb",
					},
				},
				debugType: "CodeView",
				signature: "NB10",
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
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v",
					tt.in.filepath, err)
			}

			debugEntry := file.Debugs[tt.in.index]
			if !reflect.DeepEqual(debugEntry, tt.out.debugEntry) {
				t.Fatalf("debug entry assertion failed, got %v, want %v",
					debugEntry, tt.out.debugEntry)
			}

			debugTypeString := debugEntry.String()
			if debugTypeString != tt.out.debugType {
				t.Fatalf("debug entry type string assertion failed, got %v, want %v",
					debugTypeString, tt.out.debugType)
			}

			cvSignature := ""
			switch debugEntry.Info.(type) {
			case CVInfoPDB70:
				cvSignature = debugEntry.Info.(CVInfoPDB70).CVSignature.String()
			case CVInfoPDB20:
				cvSignature = debugEntry.Info.(CVInfoPDB20).CVHeader.Signature.String()
			}
			if cvSignature != tt.out.signature {
				t.Fatalf("debug CV signature assertion failed, got %v, want %v",
					cvSignature, tt.out.signature)
			}
		})
	}
}

func TestDebugDirectoryPOGO(t *testing.T) {

	type TestPOGO struct {
		imgDebugEntry ImageDebugDirectory
		entriesCount  int
		debugType     string
		POGOItemIndex int
		POGOItem      ImagePGOItem
		POGOSignature string
	}

	tests := []struct {
		in  TestDebugIn
		out TestPOGO
	}{
		{
			TestDebugIn{
				index:    1,
				filepath: getAbsoluteFilePath("test/kernel32.dll"),
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
				debugType:     "POGO",
				entriesCount:  60,
				POGOItemIndex: 0,
				POGOItem: ImagePGOItem{
					RVA:  0x1000,
					Size: 0x280,
					Name: ".text$lp00kernel32.dll!20_pri7",
				},
				POGOSignature: "PGU",
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
				t.Errorf("debug entry assertion failed, got %v, want %v",
					imgDebugEntry, tt.out.imgDebugEntry)
			}

			debugTypeString := file.Debugs[tt.in.index].String()
			if debugTypeString != tt.out.debugType {
				t.Fatalf("debug type assertion failed, got %v, want %v",
					debugTypeString, tt.out.debugType)
			}

			pogo := file.Debugs[tt.in.index].Info.(POGO)
			pogoItem := pogo.Entries[tt.out.POGOItemIndex]
			if !reflect.DeepEqual(pogoItem, tt.out.POGOItem) {
				t.Errorf("debug pogo entry assertion failed, got %v, want %v",
					pogoItem, tt.out.POGOItemIndex)
			}

			pogoItemSignature := pogo.Signature.String()
			if pogoItemSignature != tt.out.POGOSignature {
				t.Fatalf("debug pogo signature string assertion failed, got %v, want %v",
					pogoItemSignature, tt.out.POGOSignature)
			}
		})
	}
}

func TestDebugDirectoryREPRO(t *testing.T) {

	type TestREPRO struct {
		debugType  string
		debugEntry DebugEntry
	}

	tests := []struct {
		in  TestDebugIn
		out TestREPRO
	}{

		{
			TestDebugIn{
				index:    2,
				filepath: getAbsoluteFilePath("test/kernel32.dll"),
			},
			TestREPRO{
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
				debugType: "REPRO",
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
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v",
					tt.in.filepath, err)
			}

			debugEntry := file.Debugs[tt.in.index]
			if !reflect.DeepEqual(debugEntry, tt.out.debugEntry) {
				t.Errorf("debug entry assertion failed, got %v, want %v",
					debugEntry, tt.out.debugEntry)
			}

			debugTypeString := debugEntry.String()
			if debugTypeString != tt.out.debugType {
				t.Fatalf("debug entry type string assertion failed, got %v, want %v",
					debugTypeString, tt.out.debugType)
			}
		})
	}
}

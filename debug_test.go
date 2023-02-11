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
					Type: "CodeView",
				},
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
					Type: "CodeView",
				},
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
				t.Fatalf("debug entry assertion failed, got %v, want %v",
					imgDebugEntry, tt.out.imgDebugEntry)
			}

			debugTypeString := file.Debugs[tt.in.index].Type
			if debugTypeString != tt.out.debugType {
				t.Fatalf("debug type assertion failed, got %v, want %v",
					debugTypeString, tt.out.debugType)
			}

			pogo := file.Debugs[tt.in.index].Info.(POGO)
			entriesCount := len(pogo.Entries)
			if entriesCount != tt.out.entriesCount {
				t.Fatalf("debug entry count failed, got %v, want %v",
					entriesCount, tt.out.entriesCount)
			}

			pogoItem := pogo.Entries[tt.out.POGOItemIndex]
			if !reflect.DeepEqual(pogoItem, tt.out.POGOItem) {
				t.Fatalf("debug pogo entry assertion failed, got %v, want %v",
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

					Type: "REPRO",
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
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v",
					tt.in.filepath, err)
			}

			debugEntry := file.Debugs[tt.in.index]
			if !reflect.DeepEqual(debugEntry, tt.out.debugEntry) {
				t.Fatalf("debug entry assertion failed, got %v, want %v",
					debugEntry, tt.out.debugEntry)
			}

		})
	}
}

func TestDebugDirectoryExDLLCharacteristics(t *testing.T) {

	type TestExDLLCharacteristics struct {
		debugEntry           DebugEntry
		exDLLCharacteristics string
	}

	tests := []struct {
		in  TestDebugIn
		out TestExDLLCharacteristics
	}{
		{
			TestDebugIn{
				index:    3,
				filepath: getAbsoluteFilePath("test/kernel32.dll"),
			},
			TestExDLLCharacteristics{
				debugEntry: DebugEntry{
					Struct: ImageDebugDirectory{
						Characteristics:  0x0,
						TimeDateStamp:    0x38b369c4,
						MajorVersion:     0x0,
						MinorVersion:     0x0,
						Type:             0x14,
						SizeOfData:       0x4,
						AddressOfRawData: 0x938b0,
						PointerToRawData: 0x922b0,
					},
					Info: DllCharacteristicsExType(0x1),
					Type: "Ex.DLL Characteristics",
				},
				exDLLCharacteristics: "CET Compatible",
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

			dllCharacteristicsExString := debugEntry.Info.(DllCharacteristicsExType).String()
			if dllCharacteristicsExString != tt.out.exDLLCharacteristics {
				t.Fatalf("debug entry DllCharacteristicsEx string assertion failed, got %v, want %v",
					dllCharacteristicsExString, tt.out.exDLLCharacteristics)
			}
		})
	}
}

func TestDebugDirectoryVCFeature(t *testing.T) {

	type TestVCFeature struct {
		debugEntry DebugEntry
	}

	tests := []struct {
		in  TestDebugIn
		out TestVCFeature
	}{
		{
			TestDebugIn{
				index:    1,
				filepath: getAbsoluteFilePath("test/00da1a2a9d9ebf447508bf6550f05f466f8eabb4ed6c4f2a524c0769b2d75bc1"),
			},
			TestVCFeature{
				debugEntry: DebugEntry{
					Struct: ImageDebugDirectory{
						Characteristics:  0x0,
						TimeDateStamp:    0x5ef47ea0,
						MajorVersion:     0x0,
						MinorVersion:     0x0,
						Type:             0xc,
						SizeOfData:       0x14,
						AddressOfRawData: 0x39d58,
						PointerToRawData: 0x39158,
					},
					Info: VCFeature{
						PreVC11: 0xa,
						CCpp:    0x115,
						Gs:      0xe4,
						Sdl:     0x0,
						GuardN:  0x115,
					},
					Type: "VC Feature",
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
				t.Fatalf("parseExportDirectory(%s) failed, reason: %v",
					tt.in.filepath, err)
			}

			debugEntry := file.Debugs[tt.in.index]
			if !reflect.DeepEqual(debugEntry, tt.out.debugEntry) {
				t.Fatalf("debug entry assertion failed, got %+v, want %+v",
					debugEntry, tt.out.debugEntry)
			}

		})
	}
}

func TestDebugDirectoryFPO(t *testing.T) {

	type TestFPO struct {
		imgDebugEntry ImageDebugDirectory
		entriesCount  int
		debugType     string
		FPODataIndex  int
		FPOData       FPOData
		FPOFrameType  string
	}

	tests := []struct {
		in  TestDebugIn
		out TestFPO
	}{
		{
			TestDebugIn{
				index:    1,
				filepath: getAbsoluteFilePath("test/jobexec.dll"),
			},
			TestFPO{
				imgDebugEntry: ImageDebugDirectory{
					Characteristics:  0x0,
					TimeDateStamp:    0x355b8e5f,
					MajorVersion:     0x0,
					MinorVersion:     0x0,
					Type:             0x3,
					SizeOfData:       0x840,
					AddressOfRawData: 0x0,
					PointerToRawData: 0xb310,
				},
				debugType:    "FPO",
				entriesCount: 131,
				FPODataIndex: 0,
				FPOData: FPOData{
					OffsetStart: 0x1bc0,
					ProcSize:    0x22,
				},
				FPOFrameType: "FPO",
			},
		},
		{
			TestDebugIn{
				index:    1,
				filepath: getAbsoluteFilePath("test/jobexec.dll"),
			},
			TestFPO{
				imgDebugEntry: ImageDebugDirectory{
					Characteristics:  0x0,
					TimeDateStamp:    0x355b8e5f,
					MajorVersion:     0x0,
					MinorVersion:     0x0,
					Type:             0x3,
					SizeOfData:       0x840,
					AddressOfRawData: 0x0,
					PointerToRawData: 0xb310,
				},
				debugType:    "FPO",
				entriesCount: 131,
				FPODataIndex: 2,
				FPOData: FPOData{
					OffsetStart:    0x1c26,
					ProcSize:       0x267,
					NumLocals:      0x104,
					ParamsSize:     0x1,
					PrologLength:   0x16,
					SavedRegsCount: 0x3,
					HasSEH:         0x0,
					UseBP:          0x1,
					Reserved:       0x0,
					FrameType:      0x3,
				},
				FPOFrameType: "Non FPO",
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
				t.Fatalf("debug entry assertion failed, got %v, want %v",
					imgDebugEntry, tt.out.imgDebugEntry)
			}

			debugTypeString := file.Debugs[tt.in.index].Type
			if debugTypeString != tt.out.debugType {
				t.Fatalf("debug type assertion failed, got %v, want %v",
					debugTypeString, tt.out.debugType)
			}

			fpo := file.Debugs[tt.in.index].Info.([]FPOData)
			entriesCount := len(fpo)
			if entriesCount != tt.out.entriesCount {
				t.Fatalf("debug entry count failed, got %v, want %v",
					entriesCount, tt.out.entriesCount)
			}

			fpoData := fpo[tt.out.FPODataIndex]
			if !reflect.DeepEqual(fpoData, tt.out.FPOData) {
				t.Fatalf("debug FPO data entry assertion failed, got %v, want %v",
					fpoData, tt.out.FPOData)
			}

			frameType := fpoData.FrameType.String()
			if frameType != tt.out.FPOFrameType {
				t.Fatalf("debug FPO frame type string assertion failed, got %v, want %v",
					frameType, tt.out.FPOFrameType)
			}
		})
	}
}

func TestDebugSectionAttributes(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{

			".00cfg",
			"CFG Check Functions Pointers",
		},
		{
			"__undefined__",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {

			secAttrString := SectionAttributeDescription(tt.in)
			if secAttrString != tt.out {
				t.Fatalf("debug section attributes description failed, got %v, want %v",
					secAttrString, tt.out)
			}
		})
	}
}

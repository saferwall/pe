// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

func TestLoadConfigDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out interface{}
	}{
		{
			in: getAbsoluteFilePath("test/pspluginwkr.dll"),
			out: ImageLoadConfigDirectory32{
				Size:           0x48,
				SecurityCookie: 0x45e44220,
				SEHandlerTable: 0x45e382e0,
				SEHandlerCount: 0x1,
			},
		},
		{
			in: getAbsoluteFilePath("test/00da1a2a9d9ebf447508bf6550f05f466f8eabb4ed6c4f2a524c0769b2d75bc1"),
			out: ImageLoadConfigDirectory32{
				Size:                        0x5c,
				SecurityCookie:              0x43D668,
				SEHandlerTable:              0x439C70,
				SEHandlerCount:              0x25,
				GuardCFCheckFunctionPointer: 0x432260,
				GuardCFFunctionTable:        0x4322D4,
				GuardCFFunctionCount:        0x90,
				GuardFlags:                  0x10013500,
			},
		},
		{
			in: getAbsoluteFilePath("test/3a081c7fe475ec68ed155c76d30cfddc4d41f7a09169810682d1c75421e98eaa"),
			out: ImageLoadConfigDirectory32{
				Size:                        0xa0,
				SecurityCookie:              0x417008,
				SEHandlerTable:              0x415410,
				SEHandlerCount:              0x2,
				GuardCFCheckFunctionPointer: 0x40e384,
				GuardFlags:                  0x100,
			},
		},

		{
			in: getAbsoluteFilePath("test/IEAdvpack.dll"),
			out: ImageLoadConfigDirectory32{
				Size:                           0xa4,
				SecurityCookie:                 0x6501b074,
				SEHandlerTable:                 0x650046d0,
				SEHandlerCount:                 0x1,
				GuardCFCheckFunctionPointer:    0x6502937c,
				GuardCFFunctionTable:           0x650010f0,
				GuardCFFunctionCount:           0x55,
				GuardFlags:                     0x10017500,
				GuardAddressTakenIATEntryTable: 0x6500129c,
				GuardAddressTakenIATEntryCount: 0x1,
				GuardLongJumpTargetTable:       0x650012a4,
				GuardLongJumpTargetCount:       0x2,
			},
		},
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: ImageLoadConfigDirectory32{
				Size:                           0xb8,
				DependentLoadFlags:             0x800,
				SecurityCookie:                 0x101f3b50,
				SEHandlerTable:                 0x10090c40,
				SEHandlerCount:                 0x3,
				GuardCFCheckFunctionPointer:    0x101f7b08,
				GuardCFFunctionTable:           0x1005ab70,
				GuardCFFunctionCount:           0xc4a,
				GuardFlags:                     0x10017500,
				GuardAddressTakenIATEntryTable: 0x1005e8e4,
				GuardAddressTakenIATEntryCount: 0xa,
				VolatileMetadataPointer:        0x10090c4c,
			},
		},
		{
			in: getAbsoluteFilePath("test/WdfCoInstaller01011.dll"),
			out: ImageLoadConfigDirectory64{
				Size:           0x70,
				SecurityCookie: 0x18000f108,
			},
		},
		{
			in: getAbsoluteFilePath("test/D2D1Debug2.dll"),
			out: ImageLoadConfigDirectory64{
				Size:                        0x94,
				SecurityCookie:              0x180061008,
				GuardCFCheckFunctionPointer: 0x180001000,
			},
		},
		{
			in: getAbsoluteFilePath("test/amdxata.sys"),
			out: ImageLoadConfigDirectory64{
				Size:                           0xa0,
				SecurityCookie:                 0x1c00030b0,
				GuardCFCheckFunctionPointer:    0x1c0005160,
				GuardCFDispatchFunctionPointer: 0x1c0005168,
				GuardCFFunctionTable:           0x1c0009000,
				GuardCFFunctionCount:           0x17,
				GuardFlags:                     0x500,
			},
		},
		{
			in: getAbsoluteFilePath("test/amdi2c.sys"),
			out: ImageLoadConfigDirectory64{
				Size:                           0xd0,
				SecurityCookie:                 0x140009090,
				GuardCFCheckFunctionPointer:    0x140008100,
				GuardCFDispatchFunctionPointer: 0x140008108,
				GuardFlags:                     0x100,
			},
		},
		{
			in: getAbsoluteFilePath("test/brave.exe"),
			out: ImageLoadConfigDirectory64{
				Size:                           0x100,
				SecurityCookie:                 0x14017b648,
				GuardCFCheckFunctionPointer:    0x140191000,
				GuardCFDispatchFunctionPointer: 0x140191008,
				GuardCFFunctionTable:           0x14016b627,
				GuardCFFunctionCount:           0x561,
				GuardFlags:                     0x500,
			},
		},
		{
			in: getAbsoluteFilePath("test/shimeng.dll"),
			out: ImageLoadConfigDirectory64{
				Size:                           0x108,
				SecurityCookie:                 0x180003000,
				GuardCFCheckFunctionPointer:    0x180002188,
				GuardCFDispatchFunctionPointer: 0x180002190,
				GuardCFFunctionTable:           0x180002198,
				GuardCFFunctionCount:           0x3,
				GuardFlags:                     0x17500,
			},
		},
		{
			in: getAbsoluteFilePath("test/kernel32.dll"),
			out: ImageLoadConfigDirectory64{
				Size:                           0x118,
				SecurityCookie:                 0x1800b3220,
				GuardCFCheckFunctionPointer:    0x180084218,
				GuardCFDispatchFunctionPointer: 0x180084220,
				GuardCFFunctionTable:           0x180084388,
				GuardCFFunctionCount:           0x5e6,
				GuardFlags:                     0x10417500,
				GuardAddressTakenIATEntryTable: 0x180086108,
				GuardAddressTakenIATEntryCount: 0x3,
				GuardEHContinuationTable:       0x180084228,
				GuardEHContinuationCount:       0x46,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			imgLoadCfgDirectory := file.LoadConfig.Struct
			if imgLoadCfgDirectory != tt.out {
				t.Fatalf("load config directory structure assertion failed, got %v, want %v",
					imgLoadCfgDirectory, tt.out)
			}

		})
	}
}

func TestLoadConfigDirectorySEHHandlers(t *testing.T) {

	tests := []struct {
		in  string
		out []uint32
	}{
		{
			in:  getAbsoluteFilePath("test/KernelBase.dll"),
			out: []uint32{0x14ad30, 0x14af40, 0x14b0d0},
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			sehHandlers := file.LoadConfig.SEH
			if !reflect.DeepEqual(sehHandlers, tt.out) {
				t.Fatalf("load config SEH handlers assertion failed, got %v, want %v",
					sehHandlers, tt.out)
			}
		})
	}
}

func TestLoadConfigDirectoryControlFlowGuardFunctions(t *testing.T) {

	type TestGFIDSEntry struct {
		entriesCount int
		entryIndex   int
		CFGFunction  CFGFunction
	}

	tests := []struct {
		in  string
		out TestGFIDSEntry
	}{
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0xc4a,
				entryIndex:   0x1,
				CFGFunction: CFGFunction{
					RVA:         0xfe2a0,
					Flags:       ImageGuardFlagExportSuppressed,
					Description: "GetCalendarInfoEx",
				},
			},
		},
		{
			in: getAbsoluteFilePath("test/kernel32.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0x5e6,
				entryIndex:   0x5d3,
				CFGFunction: CFGFunction{
					RVA:         0x71390,
					Flags:       ImageGuardFlagExportSuppressed,
					Description: "QuirkIsEnabledForPackage2Worker",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {

			ops := Options{Fast: false}
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			gfids := file.LoadConfig.GFIDS
			if len(gfids) != tt.out.entriesCount {
				t.Fatalf("load config GFIDS entries count assert failed, got %v, want %v",
					len(gfids), tt.out.entriesCount)
			}

			guardedFunction := gfids[tt.out.entryIndex]
			if !reflect.DeepEqual(guardedFunction, tt.out.CFGFunction) {
				t.Fatalf("load config GFIDS entry assertion failed, got %v, want %v",
					guardedFunction, tt.out.CFGFunction)
			}
		})
	}
}

func TestLoadConfigDirectoryControlFlowGuardIAT(t *testing.T) {

	type TestGFIDSEntry struct {
		entriesCount int
		entryIndex   int
		CFGFunction  CFGIATEntry
	}

	tests := []struct {
		in  string
		out TestGFIDSEntry
	}{
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0xa,
				entryIndex:   0x9,
				CFGFunction: CFGIATEntry{
					RVA:         0x1f7924,
					IATValue:    0x80000008,
					INTValue:    0x80000008,
					Description: "ntdll.dll!#8",
				},
			},
		},
		{
			in: getAbsoluteFilePath("test/kernel32.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0x3,
				entryIndex:   0x2,
				CFGFunction: CFGIATEntry{
					RVA:         0x83838,
					IATValue:    0xac0e0,
					INTValue:    0xac0e0,
					Description: "ntdll.dll!RtlGetLengthWithoutLastFullDosOrNtPathElement",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {

			ops := Options{Fast: false}
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			cfgIAT := file.LoadConfig.CFGIAT
			if len(cfgIAT) != tt.out.entriesCount {
				t.Fatalf("load config CFG IAT entries count assert failed, got %v, want %v",
					len(cfgIAT), tt.out.entriesCount)
			}

			cfgIATEntry := cfgIAT[tt.out.entryIndex]
			if !reflect.DeepEqual(cfgIATEntry, tt.out.CFGFunction) {
				t.Fatalf("load config CFG IAT entry assertion failed, got %v, want %v",
					cfgIATEntry, tt.out.CFGFunction)
			}
		})
	}
}

func TestLoadConfigDirectoryControlFlowGuardLongJump(t *testing.T) {

	tests := []struct {
		in  string
		out []uint32
	}{
		{
			in:  getAbsoluteFilePath("test/IEAdvpack.dll"),
			out: []uint32{0x13EDD, 0x1434F},
		},
		{
			in:  getAbsoluteFilePath("test/PSCRIPT5.DLL"),
			out: []uint32{0x3FE11, 0x401F8, 0x4077D, 0x40B53, 0x40DFD, 0x40FB3},
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			cfgLongJumpTargetTable := file.LoadConfig.CFGLongJump
			if !reflect.DeepEqual(cfgLongJumpTargetTable, tt.out) {
				t.Fatalf("load config CFG long jump target table assertion failed, got %v, want %v",
					cfgLongJumpTargetTable, tt.out)
			}
		})
	}
}

func TestLoadConfigDirectoryHybridPE(t *testing.T) {

	type TestCHPE struct {
		imgCHPEMetadata ImageCHPEMetadataX86
		codeRanges      []CodeRange
		compilerIAT     CompilerIAT
	}

	tests := []struct {
		in  string
		out TestCHPE
	}{
		{
			in: getAbsoluteFilePath("test/msyuv.dll"),
			out: TestCHPE{
				imgCHPEMetadata: ImageCHPEMetadataX86{
					Version:                                  0x4,
					CHPECodeAddressRangeOffset:               0x26f8,
					CHPECodeAddressRangeCount:                0x4,
					WoWA64ExceptionHandlerFunctionPtr:        0x1000c,
					WoWA64DispatchCallFunctionPtr:            0x10000,
					WoWA64DispatchIndirectCallFunctionPtr:    0x10004,
					WoWA64DispatchIndirectCallCfgFunctionPtr: 0x10008,
					WoWA64DispatchRetFunctionPtr:             0x10010,
					WoWA64DispatchRetLeafFunctionPtr:         0x10014,
					WoWA64DispatchJumpFunctionPtr:            0x10018,
					CompilerIATPointer:                       0x11000,
					WoWA64RDTSCFunctionPtr:                   0x1001c,
				},
				codeRanges: []CodeRange{
					{
						Begin:   0x1000,
						Length:  0x10,
						Machine: 0x0,
					},
					{
						Begin:   0x2a00,
						Length:  0x4e28,
						Machine: 0x1,
					},
					{
						Begin:   0x8000,
						Length:  0x4b1,
						Machine: 0x0,
					},
					{
						Begin:   0x9000,
						Length:  0x2090,
						Machine: 0x1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {

			ops := Options{Fast: false}
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			chpe := file.LoadConfig.CHPE
			if chpe.CHPEMetadata != tt.out.imgCHPEMetadata {
				t.Fatalf("load config CHPE metadata assertion failed, got %v, want %v",
					chpe.CHPEMetadata, tt.out.imgCHPEMetadata)
			}

			if !reflect.DeepEqual(chpe.CodeRanges, tt.out.codeRanges) {
				t.Fatalf("load config CHPE code ranges assertion failed, got %v, want %v",
					chpe.CodeRanges, tt.out.codeRanges)
			}

			// TODO: test compiler IAT.
		})
	}
}

func TestLoadConfigDirectoryDVRT(t *testing.T) {

	type TestDVRT struct {
		imgDynRelocTable  ImageDynamicRelocationTable
		relocEntriesCount int
	}

	tests := []struct {
		in  string
		out TestDVRT
	}{
		{
			in: getAbsoluteFilePath("test/WdBoot.sys"),
			out: TestDVRT{
				imgDynRelocTable: ImageDynamicRelocationTable{
					Version: 0x1,
					Size:    0x2dc,
				},
				relocEntriesCount: 0x2,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			DVRT := file.LoadConfig.DVRT
			if DVRT.ImageDynamicRelocationTable != tt.out.imgDynRelocTable {
				t.Fatalf("load config DVRT header assertion failed, got %v, want %v",
					DVRT.ImageDynamicRelocationTable, tt.out.imgDynRelocTable)
			}

			if len(DVRT.Entries) != tt.out.relocEntriesCount {
				t.Fatalf("load config DVRT entries count  assertion failed, got %v, want %v",
					len(DVRT.Entries), tt.out.relocEntriesCount)
			}
		})
	}
}

func TestLoadConfigDirectoryDVRTRetpolineType(t *testing.T) {

	type DVRTRetpolineType struct {
		relocEntryIdx   int
		imgDynReloc     interface{}
		RelocBlockCount int
		relocBlockIdx   int
		relocBlock      RelocBlock
	}

	tests := []struct {
		in  string
		out DVRTRetpolineType
	}{
		{
			in: getAbsoluteFilePath("test/WdBoot.sys"),
			out: DVRTRetpolineType{
				relocEntryIdx: 0x0,
				imgDynReloc: ImageDynamicRelocation64{
					Symbol:        0x3,
					BaseRelocSize: 0x278,
				},
				RelocBlockCount: 0x7,
				relocBlockIdx:   0x0,
				relocBlock: RelocBlock{
					ImgBaseReloc: ImageBaseRelocation{
						VirtualAddress: 0x2000,
						SizeOfBlock:    0xc,
					},
					TypeOffsets: []interface{}{
						ImageImportControlTransferDynamicRelocation{
							PageRelativeOffset: 0x611,
							IndirectCall:       0x0,
							IATIndex:           0x28,
						},
					},
				},
			},
		},
		{
			in: getAbsoluteFilePath("test/WdBoot.sys"),
			out: DVRTRetpolineType{
				relocEntryIdx: 0x1,
				imgDynReloc: ImageDynamicRelocation64{
					Symbol:        0x4,
					BaseRelocSize: 0x4c,
				},
				RelocBlockCount: 0x5,
				relocBlockIdx:   0x4,
				relocBlock: RelocBlock{
					ImgBaseReloc: ImageBaseRelocation{
						VirtualAddress: 0xb000,
						SizeOfBlock:    0xc,
					},
					TypeOffsets: []interface{}{
						ImageIndirectControlTransferDynamicRelocation{
							PageRelativeOffset: 0x58e,
							IndirectCall:       0x1,
							CfgCheck:           0x1,
						},
					},
				},
			},
		},
		{
			in: getAbsoluteFilePath("test/acpi.sys"),
			out: DVRTRetpolineType{
				relocEntryIdx: 0x2,
				imgDynReloc: ImageDynamicRelocation64{
					Symbol:        0x5,
					BaseRelocSize: 0x4c,
				},
				RelocBlockCount: 0x6,
				relocBlockIdx:   0x5,
				relocBlock: RelocBlock{
					ImgBaseReloc: ImageBaseRelocation{
						VirtualAddress: 0x43000,
						SizeOfBlock:    0xc,
					},
					TypeOffsets: []interface{}{
						ImageSwitchableBranchDynamicRelocation{
							PageRelativeOffset: 0xd1,
							RegisterNumber:     0x1,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			DVRT := file.LoadConfig.DVRT
			relocEntry := DVRT.Entries[tt.out.relocEntryIdx]
			if relocEntry.ImageDynamicRelocation != tt.out.imgDynReloc {
				t.Fatalf("load config DVRT reloc entry imaged dynamic relocation assertion failed, got %#v, want %#v",
					relocEntry.ImageDynamicRelocation, tt.out.imgDynReloc)
			}

			if len(relocEntry.RelocBlocks) != tt.out.RelocBlockCount {
				t.Fatalf("load config DVRT reloc block count dynamic relocation assertion failed, got %v, want %v",
					len(relocEntry.RelocBlocks), tt.out.RelocBlockCount)
			}

			relocBlock := relocEntry.RelocBlocks[tt.out.relocBlockIdx]
			if !reflect.DeepEqual(relocBlock, tt.out.relocBlock) {
				t.Fatalf("load config DVRT reloc block assertion failed, got %#v, want %#v",
					relocBlock, tt.out.relocBlock)
			}
		})
	}
}

func TestLoadConfigDirectoryEnclave(t *testing.T) {

	tests := []struct {
		in  string
		out Enclave
	}{
		{
			in: getAbsoluteFilePath("test/SgrmEnclave_secure.dll"),
			out: Enclave{
				Config: ImageEnclaveConfig64{
					Size:                      0x50,
					MinimumRequiredConfigSize: 0x4c,
					NumberOfImports:           0x4,
					ImportList:                0x55224,
					ImportEntrySize:           0x50,
					FamilyID:                  [ImageEnclaveShortIDLength]uint8{0xb1, 0x35, 0x7c, 0x2b, 0x69, 0x9f, 0x47, 0xf9, 0xbb, 0xc9, 0x4f, 0x44, 0xf2, 0x54, 0xdb, 0x9d},
					ImageID:                   [ImageEnclaveShortIDLength]uint8{0x24, 0x56, 0x46, 0x36, 0xcd, 0x4a, 0x4a, 0xd8, 0x86, 0xa2, 0xf4, 0xec, 0x25, 0xa9, 0x72, 0x2},
					ImageVersion:              0x1,
					SecurityVersion:           0x1,
					EnclaveSize:               0x10000000,
					NumberOfThreads:           0x8,
					EnclaveFlags:              0x1,
				},
				Imports: []ImageEnclaveImport{
					{
						MatchType:  0x0,
						ImportName: 0xffff,
					},
					{
						MatchType: 0x4,
						ImageID: [ImageEnclaveShortIDLength]uint8{
							0xf0, 0x3c, 0xcd, 0xa7, 0xe8, 0x7b, 0x46, 0xeb, 0xaa, 0xe7, 0x1f, 0x13, 0xd5, 0xcd, 0xde, 0x5d},
						ImportName: 0x5b268,
					},
					{
						MatchType: 0x4,
						ImageID: [ImageEnclaveShortIDLength]uint8{
							0x20, 0x27, 0xbd, 0x68, 0x75, 0x59, 0x49, 0xb7, 0xbe, 0x6, 0x34, 0x50, 0xe2, 0x16, 0xd7, 0xed},
						ImportName: 0x5b428,
					},
					{
						MatchType: 0x4,
						ImageID: [ImageEnclaveShortIDLength]uint8{
							0x72, 0x84, 0x41, 0x72, 0x67, 0xa8, 0x4e, 0x8d, 0xbf, 0x1, 0x28, 0x4b, 0x7, 0x43, 0x2b, 0x1e},
						ImportName: 0x5b63c,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			enclave := file.LoadConfig.Enclave
			if !reflect.DeepEqual(*enclave, tt.out) {
				t.Fatalf("load config enclave assertion failed, got %#v, want %#v",
					enclave, tt.out)
			}

		})
	}
}

func TestLoadConfigDirectoryVolatileMetadata(t *testing.T) {

	type TestVolatileMetadata struct {
		imgVolatileMetadata ImageVolatileMetadata
		accessRVATableCount int
		accessRVATableIndex int
		accessRVAEntry      uint32
		infoRangeTableCount int
		infoRangeTableIndex int
		infoRangeEntry      RangeTableEntry
	}

	tests := []struct {
		in  string
		out TestVolatileMetadata
	}{
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: TestVolatileMetadata{
				imgVolatileMetadata: ImageVolatileMetadata{
					Size:                       0x18,
					Version:                    0x1,
					VolatileAccessTable:        0x00090C64,
					VolatileAccessTableSize:    0x00002E48,
					VolatileInfoRangeTable:     0x00093AAC,
					VolatileInfoRangeTableSize: 0x000001D0,
				},
				accessRVATableCount: 0xB92,
				accessRVATableIndex: 0xB91,
				accessRVAEntry:      0x1DF998,
				infoRangeTableCount: 0x3A,
				infoRangeTableIndex: 0x39,
				infoRangeEntry: RangeTableEntry{
					RVA:  0x16BB10,
					Size: 0x75550,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			volatileMetadata := file.LoadConfig.VolatileMetadata
			if volatileMetadata.Struct != tt.out.imgVolatileMetadata {
				t.Fatalf("load config image volatile metadata assertion failed, got %v, want %v",
					volatileMetadata, tt.out.imgVolatileMetadata)
			}

			if len(volatileMetadata.AccessRVATable) != tt.out.accessRVATableCount {
				t.Fatalf("load config access RVA table entries count assert failed, got %v, want %v",
					len(volatileMetadata.AccessRVATable), tt.out.accessRVATableCount)
			}

			accessRVAEntry := volatileMetadata.AccessRVATable[tt.out.accessRVATableIndex]
			if accessRVAEntry != tt.out.accessRVAEntry {
				t.Fatalf("load config access RVA table entry assertion failed, got %v, want %v",
					accessRVAEntry, tt.out.accessRVAEntry)
			}

			if len(volatileMetadata.InfoRangeTable) != tt.out.infoRangeTableCount {
				t.Fatalf("load config info range table entries count assert failed, got %v, want %v",
					len(volatileMetadata.InfoRangeTable), tt.out.infoRangeTableCount)
			}

			infoRangeEntry := volatileMetadata.InfoRangeTable[tt.out.infoRangeTableIndex]
			if infoRangeEntry != tt.out.infoRangeEntry {
				t.Fatalf("load config info range table entry assertion failed, got %v, want %v",
					infoRangeEntry, tt.out.infoRangeEntry)
			}
		})
	}
}

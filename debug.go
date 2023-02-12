// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The following values are defined for the Type field of the debug directory entry:
const (
	// An unknown value that is ignored by all tools.
	ImageDebugTypeUnknown = 0

	// The COFF debug information (line numbers, symbol table, and string table).
	// This type of debug information is also pointed to by fields in the file headers.
	ImageDebugTypeCOFF = 1

	// The Visual C++ debug information.
	ImageDebugTypeCodeView = 2

	// The frame pointer omission (FPO) information. This information tells the
	// debugger how to interpret nonstandard stack frames, which use the EBP
	// register for a purpose other than as a frame pointer.
	ImageDebugTypeFPO = 3

	// The location of DBG file.
	ImageDebugTypeMisc = 4

	// A copy of .pdata section.
	ImageDebugTypeException = 5

	// Reserved.
	ImageDebugTypeFixup = 6

	// The mapping from an RVA in image to an RVA in source image.
	ImageDebugTypeOMAPToSrc = 7

	// The mapping from an RVA in source image to an RVA in image.
	ImageDebugTypeOMAPFromSrc = 8

	// Reserved for Borland.
	ImageDebugTypeBorland = 9

	// Reserved.
	ImageDebugTypeReserved = 10

	// Reserved.
	ImageDebugTypeCLSID = 11

	// Visual C++ features (/GS counts /sdl counts and guardN counts).
	ImageDebugTypeVCFeature = 12

	// Pogo aka PGO aka Profile Guided Optimization.
	ImageDebugTypePOGO = 13

	// Incremental Link Time Code Generation (iLTCG).
	ImageDebugTypeILTCG = 14

	// Intel MPX.
	ImageDebugTypeMPX = 15

	// PE determinism or reproducibility.
	ImageDebugTypeRepro = 16

	// Extended DLL characteristics bits.
	ImageDebugTypeExDllCharacteristics = 20
)

const (
	// CVSignatureRSDS represents the CodeView signature 'SDSR'.
	CVSignatureRSDS = 0x53445352

	// CVSignatureNB10 represents the CodeView signature 'NB10'.
	CVSignatureNB10 = 0x3031424e
)

const (
	// FrameFPO indicates a frame of type FPO.
	FrameFPO = 0x0

	// FrameTrap indicates a frame of type Trap.
	FrameTrap = 0x1

	// FrameTSS indicates a frame of type TSS.
	FrameTSS = 0x2

	// FrameNonFPO indicates a frame of type Non-FPO.
	FrameNonFPO = 0x3
)

// DllCharacteristicsExType represents a DLL Characteristics type.
type DllCharacteristicsExType uint32

const (
	// ImageDllCharacteristicsExCETCompat indicates that the image is CET
	// compatible.
	ImageDllCharacteristicsExCETCompat = 0x0001
)

const (
	// POGOTypePGU represents a signature for an undocumented PGO sub type.
	POGOTypePGU = 0x50475500
	// POGOTypePGI represents a signature for an undocumented PGO sub type.
	POGOTypePGI = 0x50474900
	// POGOTypePGO represents a signature for an undocumented PGO sub type.
	POGOTypePGO = 0x50474F00
	// POGOTypeLTCG represents a signature for an undocumented PGO sub type.
	POGOTypeLTCG = 0x4c544347
)

// ImageDebugDirectoryType represents the type of a debug directory.
type ImageDebugDirectoryType uint32

// ImageDebugDirectory represents the IMAGE_DEBUG_DIRECTORY structure.
// This directory indicates what form of debug information is present
// and where it is. This directory consists of an array of debug directory
// entries whose location and size are indicated in the image optional header.
type ImageDebugDirectory struct {
	// Reserved, must be 0.
	Characteristics uint32 `json:"characteristics"`

	// The time and date that the debug data was created.
	TimeDateStamp uint32 `json:"time_date_stamp"`

	// The major version number of the debug data format.
	MajorVersion uint16 `json:"major_version"`

	// The minor version number of the debug data format.
	MinorVersion uint16 `json:"minor_version"`

	// The format of debugging information. This field enables support of
	// multiple debuggers.
	Type ImageDebugDirectoryType `json:"type"`

	// The size of the debug data (not including the debug directory itself).
	SizeOfData uint32 `json:"size_of_data"`

	//The address of the debug data when loaded, relative to the image base.
	AddressOfRawData uint32 `json:"address_of_raw_data"`

	// The file pointer to the debug data.
	PointerToRawData uint32 `json:"pointer_to_raw_data"`
}

// DebugEntry wraps ImageDebugDirectory to include debug directory type.
type DebugEntry struct {
	// Points to the image debug entry structure.
	Struct ImageDebugDirectory `json:"struct"`

	// Holds specific information about the debug type entry.
	Info interface{} `json:"info"`

	// Type of the debug entry.
	Type string `json:"type"`
}

// GUID is a 128-bit value consisting of one group of 8 hexadecimal digits,
// followed by three groups of 4 hexadecimal digits each, followed by one
// group of 12 hexadecimal digits.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// CVSignature represents a CodeView signature.
type CVSignature uint32

// CVInfoPDB70 represents the the CodeView data block of a PDB 7.0 file.
type CVInfoPDB70 struct {
	// CodeView signature, equal to `RSDS`.
	CVSignature CVSignature `json:"cv_signature"`

	// A unique identifier, which changes with every rebuild of the executable and PDB file.
	Signature GUID `json:"signature"`

	// Ever-incrementing value, which is initially set to 1 and incremented every
	// time when a part of the PDB file is updated without rewriting the whole file.
	Age uint32 `json:"age"`

	// Null-terminated name of the PDB file. It can also contain full or partial
	// path to the file.
	PDBFileName string `json:"pdb_file_name"`
}

// CVHeader represents the the CodeView header struct to the PDB 2.0 file.
type CVHeader struct {
	// CodeView signature, equal to `NB10`.
	Signature CVSignature `json:"signature"`

	// CodeView offset. Set to 0, because debug information is stored in a
	// separate file.
	Offset uint32 `json:"offset"`
}

// CVInfoPDB20 represents the the CodeView data block of a PDB 2.0 file.
type CVInfoPDB20 struct {
	// Points to the CodeView header structure.
	CVHeader CVHeader `json:"cv_header"`

	// The time when debug information was created (in seconds since 01.01.1970).
	Signature uint32 `json:"signature"`

	// Ever-incrementing value, which is initially set to 1 and incremented every
	// time when a part of the PDB file is updated without rewriting the whole file.
	Age uint32 `json:"age"`

	// Null-terminated name of the PDB file. It can also contain full or partial
	// path to the file.
	PDBFileName string `json:"pdb_file_name"`
}

// FPOFrameType represents the type of a FPO frame.
type FPOFrameType uint8

// FPOData represents the stack frame layout for a function on an x86 computer when
// frame pointer omission (FPO) optimization is used. The structure is used to locate
// the base of the call frame.
type FPOData struct {
	// The offset of the first byte of the function code.
	OffsetStart uint32 `json:"offset_start"`

	// The number of bytes in the function.
	ProcSize uint32 `json:"proc_size"`

	// The number of local variables.
	NumLocals uint32 `json:"num_locals"`

	// The size of the parameters, in DWORDs.
	ParamsSize uint16 `json:"params_size"`

	// The number of bytes in the function prolog code.
	PrologLength uint8 `json:"prolog_length"`

	// The number of registers saved.
	SavedRegsCount uint8 `json:"saved_regs_count"`

	// A variable that indicates whether the function uses structured exception handling.
	HasSEH uint8 `json:"has_seh"`

	// A variable that indicates whether the EBP register has been allocated.
	UseBP uint8 `json:"use_bp"`

	// Reserved for future use.
	Reserved uint8 `json:"reserved"`

	// A variable that indicates the frame type.
	FrameType FPOFrameType `json:"frame_type"`
}

// ImagePGOItem represents the _IMAGE_POGO_INFO structure.
type ImagePGOItem struct {
	RVA  uint32 `json:"rva"`
	Size uint32 `json:"size"`
	Name string `json:"name"`
}

// POGOType represents a POGO type.
type POGOType uint32

// POGO structure contains information related to the Profile Guided Optimization.
// PGO is an approach to optimization where the compiler uses profile information
// to make better optimization decisions for the program.
type POGO struct {
	// Signature represents the PGO sub type.
	Signature POGOType       `json:"signature"`
	Entries   []ImagePGOItem `json:"entries"`
}

type VCFeature struct {
	PreVC11 uint32 `json:"pre_vc11"`
	CCpp    uint32 `json:"C/C++"`
	Gs      uint32 `json:"/GS"`
	Sdl     uint32 `json:"/sdl"`
	GuardN  uint32 `json:"guardN"`
}

type REPRO struct {
	Size uint32 `json:"size"`
	Hash []byte `json:"hash"`
}

// ImageDebugMisc represents the IMAGE_DEBUG_MISC structure.
type ImageDebugMisc struct {
	// The type of data carried in the `Data` field.
	DataType uint32 `json:"data_type"`

	// The length of this structure in bytes, including the entire Data field
	// and its NUL terminator (rounded to four byte multiple.)
	Length uint32 `json:"length"`

	// The encoding of the Data field. True if data is unicode string.
	Unicode bool `json:"unicode"`

	// Reserved.
	Reserved [3]byte `json:"reserved"`

	// Actual data.
	Data string `json:"data"`
}

// Image files contain an optional debug directory that indicates what form of
// debug information is present and where it is. This directory consists of an
// array of debug directory entries whose location and size are indicated in the
// image optional header.  The debug directory can be in a discardable .debug
// section (if one exists), or it can be included in any other section in the
// image file, or not be in a section at all.
func (pe *File) parseDebugDirectory(rva, size uint32) error {

	debugEntry := DebugEntry{}
	debugDir := ImageDebugDirectory{}
	errorMsg := fmt.Sprintf("Invalid debug information. Can't read data at RVA: 0x%x", rva)
	debugDirSize := uint32(binary.Size(debugDir))
	debugDirsCount := size / debugDirSize

	for i := uint32(0); i < debugDirsCount; i++ {
		offset := pe.GetOffsetFromRva(rva + debugDirSize*i)
		err := pe.structUnpack(&debugDir, offset, debugDirSize)
		if err != nil {
			return errors.New(errorMsg)
		}

		switch debugDir.Type {
		case ImageDebugTypeCodeView:
			debugSignature, err := pe.ReadUint32(debugDir.PointerToRawData)
			if err != nil {
				continue
			}

			if debugSignature == CVSignatureRSDS {
				// PDB 7.0
				pdb := CVInfoPDB70{CVSignature: CVSignatureRSDS}

				// Extract the GUID.
				offset := debugDir.PointerToRawData + 4
				guidSize := uint32(binary.Size(pdb.Signature))
				err = pe.structUnpack(&pdb.Signature, offset, guidSize)
				if err != nil {
					continue
				}

				// Extract the age.
				offset += guidSize
				pdb.Age, err = pe.ReadUint32(offset)
				if err != nil {
					continue
				}
				offset += 4

				// PDB file name.
				pdbFilenameSize := debugDir.SizeOfData - 24 - 1

				// pdbFileName_size can be negative here, as seen in the malware
				// sample with MD5 hash: 7c297600870d026c014d42596bb9b5fd
				// Checking for positive size here to ensure proper parsing.
				if pdbFilenameSize > 0 {
					pdbFilename := make([]byte, pdbFilenameSize)
					err = pe.structUnpack(&pdbFilename, offset, pdbFilenameSize)
					if err != nil {
						continue
					}
					pdb.PDBFileName = string(pdbFilename)
				}

				// Include these extra information.
				debugEntry.Info = pdb

			} else if debugSignature == CVSignatureNB10 {
				// PDB 2.0.
				cvHeader := CVHeader{}
				offset := debugDir.PointerToRawData
				err = pe.structUnpack(&cvHeader, offset, size)
				if err != nil {
					continue
				}

				pdb := CVInfoPDB20{CVHeader: cvHeader}

				// Extract the signature.
				pdb.Signature, err = pe.ReadUint32(offset + 8)
				if err != nil {
					continue
				}

				// Extract the age.
				pdb.Age, err = pe.ReadUint32(offset + 12)
				if err != nil {
					continue
				}
				offset += 16

				pdbFilenameSize := debugDir.SizeOfData - 16 - 1
				if pdbFilenameSize > 0 {
					pdbFilename := make([]byte, pdbFilenameSize)
					err = pe.structUnpack(&pdbFilename, offset, pdbFilenameSize)
					if err != nil {
						continue
					}
					pdb.PDBFileName = string(pdbFilename)
				}

				// Include these extra information.
				debugEntry.Info = pdb
			}
		case ImageDebugTypePOGO:
			pogoSignature, err := pe.ReadUint32(debugDir.PointerToRawData)
			if err != nil {
				continue
			}

			pogo := POGO{}

			switch pogoSignature {
			case 0x0, POGOTypePGU, POGOTypePGI, POGOTypePGO, POGOTypeLTCG:
				// TODO: Some files like 00da1a2a9d9ebf447508bf6550f05f466f8eabb4ed6c4f2a524c0769b2d75bc1
				// have a POGO signature of 0x0. To be reverse engineered.
				pogo.Signature = POGOType(pogoSignature)
				offset = debugDir.PointerToRawData + 4
				c := uint32(0)
				for c < debugDir.SizeOfData-4 {

					pogoEntry := ImagePGOItem{}
					pogoEntry.RVA, err = pe.ReadUint32(offset)
					if err != nil {
						break
					}
					offset += 4

					pogoEntry.Size, err = pe.ReadUint32(offset)
					if err != nil {
						break
					}
					offset += 4

					pogoEntry.Name = string(pe.GetStringFromData(0, pe.data[offset:offset+64]))

					pogo.Entries = append(pogo.Entries, pogoEntry)
					offset += uint32(len(pogoEntry.Name))

					// Make sure offset is aligned to 4 bytes.
					padding := 4 - (offset % 4)
					c += 4 + 4 + uint32(len(pogoEntry.Name)) + padding
					offset += padding
				}

				debugEntry.Info = pogo
			}
		case ImageDebugTypeVCFeature:
			vcf := VCFeature{}
			size := uint32(binary.Size(vcf))
			err := pe.structUnpack(&vcf, debugDir.PointerToRawData, size)
			if err != nil {
				continue
			}
			debugEntry.Info = vcf
		case ImageDebugTypeRepro:
			repro := REPRO{}
			offset := debugDir.PointerToRawData

			// Extract the size.
			repro.Size, err = pe.ReadUint32(offset)
			if err != nil {
				continue
			}

			// Extract the hash.
			repro.Hash, err = pe.ReadBytesAtOffset(offset+4, repro.Size)
			if err != nil {
				continue
			}
			debugEntry.Info = repro
		case ImageDebugTypeFPO:
			offset := debugDir.PointerToRawData
			size := uint32(16)
			fpoEntries := []FPOData{}
			c := uint32(0)
			for c < debugDir.SizeOfData {
				fpo := FPOData{}
				fpo.OffsetStart, err = pe.ReadUint32(offset)
				if err != nil {
					break
				}

				fpo.ProcSize, err = pe.ReadUint32(offset + 4)
				if err != nil {
					break
				}

				fpo.NumLocals, err = pe.ReadUint32(offset + 8)
				if err != nil {
					break
				}

				fpo.ParamsSize, err = pe.ReadUint16(offset + 12)
				if err != nil {
					break
				}

				fpo.PrologLength, err = pe.ReadUint8(offset + 14)
				if err != nil {
					break
				}

				attributes, err := pe.ReadUint16(offset + 15)
				if err != nil {
					break
				}

				//
				// UChar  cbRegs :3;  /* # regs saved */
				// UChar  fHasSEH:1;  /* Structured Exception Handling */
				// UChar  fUseBP :1;  /* EBP has been used */
				// UChar  reserved:1;
				// UChar  cbFrame:2;  /* frame type */
				//

				// The lowest 3 bits
				fpo.SavedRegsCount = uint8(attributes & 0x7)

				// The next bit.
				fpo.HasSEH = uint8(attributes & 0x8 >> 3)

				// The next bit.
				fpo.UseBP = uint8(attributes & 0x10 >> 4)

				// The next bit.
				fpo.Reserved = uint8(attributes & 0x20 >> 5)

				// The next 2 bits.
				fpo.FrameType = FPOFrameType(attributes & 0xC0 >> 6)

				fpoEntries = append(fpoEntries, fpo)
				c += size
				offset += 16
			}
			debugEntry.Info = fpoEntries
		case ImageDebugTypeExDllCharacteristics:
			exDllChar, err := pe.ReadUint32(debugDir.PointerToRawData)
			if err != nil {
				continue
			}

			debugEntry.Info = DllCharacteristicsExType(exDllChar)
		}

		debugEntry.Struct = debugDir
		debugEntry.Type = debugDir.Type.String()
		pe.Debugs = append(pe.Debugs, debugEntry)
	}

	if len(pe.Debugs) > 0 {
		pe.HasDebug = true
	}

	return nil
}

// SectionAttributeDescription maps a section attribute to a friendly name.
func SectionAttributeDescription(section string) string {
	sectionNameMap := map[string]string{
		".00cfg":                               "CFG Check Functions Pointers",
		".bss$00":                              "Uninit.data in phaseN of Pri7",
		".bss$dk00":                            "PGI: Uninit.data may be not const",
		".bss$dk01":                            "PGI: Uninit.data may be not const",
		".bss$pr00":                            "PGI: Uninit.data only for read",
		".bss$pr03":                            "PGI: Uninit.data only for read",
		".bss$zz":                              "PGO: Dead uninit.data",
		".CRT$XCA":                             "First C++ Initializer",
		".CRT$XCZ":                             "Last C++ Initializer",
		".xdata$x":                             "EH data",
		".gfids$y":                             "CFG Functions table",
		".CRT$XCAA":                            "Startup C++ Initializer",
		".CRT$XCC":                             "Global initializer: init_seg(compiler)",
		".CRT$XCL":                             "Global initializer: init_seg(lib)",
		".CRT$XCU":                             "Global initializer: init_seg(user)",
		".CRT$XDA":                             "First Dynamic TLS Initializer",
		".CRT$XDZ":                             "Last Dynamic TLS Initializer",
		".CRT$XIA":                             "First C Initializer",
		".CRT$XIAA":                            "Startup C Initializer",
		".CRT$XIAB":                            "PGO C Initializer",
		".CRT$XIAC":                            "Post-PGO C Initializer",
		".CRT$XIC":                             "CRT C Initializers",
		".CRT$XIYA":                            "VCCorLib Threading Model Initializer",
		".CRT$XIYAA":                           "XAML Designer Threading Model Override Initializer",
		".CRT$XIYB":                            "VCCorLib Main Initializer",
		".CRT$XIZ":                             "Last C Initializer",
		".CRT$XLA":                             "First Loader TLS Callback",
		".CRT$XLC":                             "CRT TLS Constructor",
		".CRT$XLD":                             "CRT TLS Terminator",
		".CRT$XLZ":                             "Last Loader TLS Callback",
		".CRT$XPA":                             "First Pre-Terminator",
		".CRT$XPB":                             "CRT ConcRT Pre-Terminator",
		".CRT$XPX":                             "CRT Pre-Terminators",
		".CRT$XPXA":                            "CRT stdio Pre-Terminator",
		".CRT$XPZ":                             "Last Pre-Terminator",
		".CRT$XTA":                             "First Terminator",
		".CRT$XTZ":                             "Last Terminator",
		".CRTMA$XCA":                           "First Managed C++ Initializer",
		".CRTMA$XCZ":                           "Last Managed C++ Initializer",
		".CRTVT$XCA":                           "First Managed VTable Initializer",
		".CRTVT$XCZ":                           "Last Managed VTable Initializer",
		".data$00":                             "Init.data in phaseN of Pri7",
		".data$dk00":                           "PGI: Init.data may be not const",
		".data$dk00$brc":                       "PGI: Init.data may be not const",
		".data$pr00":                           "PGI: Init.data only for read",
		".data$r":                              "RTTI Type Descriptors",
		".data$zz":                             "PGO: Dead init.data",
		".data$zz$brc":                         "PGO: Dead init.data",
		".didat$2":                             "Delay Import Descriptors",
		".didat$3":                             "Delay Import Final NULL Entry",
		".didat$4":                             "Delay Import INT",
		".didat$5":                             "Delay Import IAT",
		".didat$6":                             "Delay Import Symbol Names",
		".didat$7":                             "Delay Import Bound IAT",
		".edata":                               "Export Table",
		".gehcont":                             "CFG EHCont Table",
		".gfids":                               "CFG Functions Table",
		".giats":                               "CFG IAT Table",
		".idata$2":                             "Import Descriptors",
		".idata$3":                             "Import Final NULL Entry",
		".idata$4":                             "Import Names Table",
		".idata$5":                             "Import Addresses Table",
		".idata$6":                             "Import Symbol and DLL Names",
		".pdata":                               "Procedure data",
		".rdata$00":                            "Readonly data in phaseN of Pri7",
		".rdata$00$brc":                        "Readonly data in phaseN of Pri7",
		".rdata$09":                            "Readonly data in phaseN of Pri7",
		".rdata$brc":                           "BaseRelocation Clustering",
		".rdata$r":                             "RTTI Data",
		".rdata$sxdata":                        "Safe SEH",
		".rdata$T":                             "TLS Header",
		".rdata$zETW0":                         "ETW Metadata Header",
		".rdata$zETW1":                         "ETW Events Metadata",
		".rdata$zETW2":                         "ETW Providers Metadata",
		".rdata$zETW9":                         "ETW Metadata Footer",
		".rdata$zz":                            "PGO: Dead Readonly Data",
		".rdata$zz$brc":                        "PGO: Dead Readonly Data",
		".rdata$zzzdbg":                        "Debug directory data",
		".rsrc$01":                             "Resources Header",
		".rsrc$02":                             "Resources Data",
		".rtc$IAA":                             "First RTC Initializer",
		".rtc$IZZ":                             "Last RTC Initializer",
		".rtc$TAA":                             "First RTC Terminator",
		".rtc$TZZ":                             "Last RTC Terminator",
		".text$di":                             "MSVC Dynamic Initializers",
		".text$lp00kernel32.dll!20_pri7":       "PGO: LoaderPhaseN warm-to-hot code",
		".text$lp01kernel32.dll!20_pri7":       "PGO: LoaderPhaseN warm-to-hot code",
		".text$lp03kernel32.dll!30_clientonly": "PGO: LoaderPhaseN warm-to-hot code",
		".text$lp04kernel32.dll!30_clientonly": "PGO: LoaderPhaseN warm-to-hot code",
		".text$lp08kernel32.dll!40_serveronly": "PGO: LoaderPhaseN warm-to-hot code",
		".text$lp09kernel32.dll!40_serveronly": "PGO: LoaderPhaseN warm-to-hot code",
		".text$lp10kernel32.dll!40_serveronly": "PGO: LoaderPhaseN warm-to-hot code",
		".text$mn":                             "Contains EP",
		".text$mn$00":                          "CFG Dispatching",
		".text$np":                             "PGO: __asm or disabled via pragma",
		".text$x":                              "EH Filters",
		".text$yd":                             "MSVC Destructors",
		".text$zy":                             "PGO: Dead Code Blocks",
		".text$zz":                             "PGO: Dead Whole Functions",
		".xdata":                               "Unwind data",
	}

	if val, ok := sectionNameMap[section]; ok {
		return val
	}

	return ""
}

// String returns a string interpretation of the FPO frame type.
func (ft FPOFrameType) String() string {
	frameTypeMap := map[FPOFrameType]string{
		FrameFPO:    "FPO",
		FrameTrap:   "Trap",
		FrameTSS:    "TSS",
		FrameNonFPO: "Non FPO",
	}

	v, ok := frameTypeMap[ft]
	if ok {
		return v
	}

	return "?"
}

// String returns the string representation of a GUID.
func (g GUID) String() string {
	return fmt.Sprintf("{%06X-%04X-%04X-%04X-%X}", g.Data1, g.Data2, g.Data3, g.Data4[0:2], g.Data4[2:])
}

// String returns the string representation of a debug entry type.
func (t ImageDebugDirectoryType) String() string {

	debugTypeMap := map[ImageDebugDirectoryType]string{
		ImageDebugTypeUnknown:              "Unknown",
		ImageDebugTypeCOFF:                 "COFF",
		ImageDebugTypeCodeView:             "CodeView",
		ImageDebugTypeFPO:                  "FPO",
		ImageDebugTypeMisc:                 "Misc",
		ImageDebugTypeException:            "Exception",
		ImageDebugTypeFixup:                "Fixup",
		ImageDebugTypeOMAPToSrc:            "OMAP To Src",
		ImageDebugTypeOMAPFromSrc:          "OMAP From Src",
		ImageDebugTypeBorland:              "Borland",
		ImageDebugTypeReserved:             "Reserved",
		ImageDebugTypeVCFeature:            "VC Feature",
		ImageDebugTypePOGO:                 "POGO",
		ImageDebugTypeILTCG:                "iLTCG",
		ImageDebugTypeMPX:                  "MPX",
		ImageDebugTypeRepro:                "REPRO",
		ImageDebugTypeExDllCharacteristics: "Ex.DLL Characteristics",
	}

	v, ok := debugTypeMap[t]
	if ok {
		return v
	}

	return "?"
}

// String returns a string interpretation of a POGO type.
func (p POGOType) String() string {
	pogoTypeMap := map[POGOType]string{
		POGOTypePGU:  "PGU",
		POGOTypePGI:  "PGI",
		POGOTypePGO:  "PGO",
		POGOTypeLTCG: "LTCG",
	}

	v, ok := pogoTypeMap[p]
	if ok {
		return v
	}

	return "?"
}

// String returns a string interpretation of a CodeView signature.
func (s CVSignature) String() string {
	cvSignatureMap := map[CVSignature]string{
		CVSignatureRSDS: "RSDS",
		CVSignatureNB10: "NB10",
	}

	v, ok := cvSignatureMap[s]
	if ok {
		return v
	}

	return "?"
}

// String returns a string interpretation of Dll Characteristics Ex.
func (flag DllCharacteristicsExType) String() string {
	dllCharacteristicsExTypeMap := map[DllCharacteristicsExType]string{
		ImageDllCharacteristicsExCETCompat: "CET Compatible",
	}

	v, ok := dllCharacteristicsExTypeMap[flag]
	if ok {
		return v
	}

	return "?"
}

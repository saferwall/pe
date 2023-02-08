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
	ImageDebugTypeReserved10 = 10

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

const (
	// ImageDllCharacteristicsExCETCompat indicates that the image is CET
	// compatible.
	ImageDllCharacteristicsExCETCompat = 0x0001
)

// POGOType represents a POGO type.
type POGOType int

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
	Type uint32 `json:"type"`

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

// CVInfoPDB70 represents the the CodeView data block of a PDB 7.0 file.
type CVInfoPDB70 struct {
	// CodeView signature, equal to `RSDS`.
	CVSignature uint32 `json:"cv_signature"`

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
	Signature uint32 `json:"signature"`

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

// FPOData represents the stack frame layout for a function on an x86 computer when
// frame pointer omission (FPO) optimization is used. The structure is used to locate
// the base of the call frame.
type FPOData struct {
	// The offset of the first byte of the function code.
	OffStart uint32 `json:"off_start"`

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
	FrameType uint8 `json:"frame_type"`
}

// ImagePGOItem represents the _IMAGE_POGO_INFO structure.
type ImagePGOItem struct {
	RVA  uint32 `json:"rva"`
	Size uint32 `json:"size"`
	Name string `json:"name"`
}

// POGO structure contains information related to the Profile Guided Optimization.
// PGO is an approach to optimization where the compiler uses profile information
// to make better optimization decisions for the program.
type POGO struct {
	// Signature represents the PGO sub type.
	Signature POGOType       `json:"signature"`
	Entries   []ImagePGOItem `json:"entries"`
}

type VCFeature struct {
	PreVC11 uint32 `json:"Pre VC 11"`
	CCpp    uint32 `json:"C/C++"`
	Gs      uint32 `json:"/GS"`
	Sdl     uint32 `json:"/sdl"`
	GuardN  uint32
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

				// GUID
				offset := debugDir.PointerToRawData + 4
				guidSize := uint32(binary.Size(pdb.Signature))
				err = pe.structUnpack(&pdb.Signature, offset, guidSize)
				if err != nil {
					continue
				}

				// Age
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
				// PDB 2.0
				cvHeader := CVHeader{}
				offset := debugDir.PointerToRawData
				err = pe.structUnpack(&cvHeader, offset, size)
				if err != nil {
					continue
				}

				pdb := CVInfoPDB20{CVHeader: cvHeader}

				// Signature
				pdb.Signature, err = pe.ReadUint32(offset + 8)
				if err != nil {
					continue
				}

				// Age
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
			case POGOTypePGU, POGOTypePGI, POGOTypePGO, POGOTypeLTCG:
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

			repro.Size, err = pe.ReadUint32(offset)
			if err != nil {
				continue
			}
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
				fpo.OffStart, err = pe.ReadUint32(offset)
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
				fpo.FrameType = uint8(attributes & 0xC0 >> 6)

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

			debugEntry.Info = exDllChar
		}

		debugEntry.Struct = debugDir
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
		".CRT$XCA":      "First C++ Initializer",
		".CRT$XCAA":     "Startup C++ Initializer",
		".CRT$XCZ":      "Last C++ Initializer",
		".CRT$XDA":      "First Dynamic TLS Initializer",
		".CRT$XDZ":      "Last Dynamic TLS Initializer",
		".CRT$XIA":      "First C Initializer",
		".CRT$XIAA":     "Startup C Initializer",
		".CRT$XIAB":     "PGO C Initializer",
		".CRT$XIAC":     "Post-PGO C Initializer",
		".CRT$XIC":      "CRT C Initializers",
		".CRT$XIYA":     "VCCorLib Threading Model Initializer",
		".CRT$XIYAA":    "XAML Designer Threading Model Override Initializer",
		".CRT$XIYB":     "VCCorLib Main Initializer",
		".CRT$XIZ":      "Last C Initializer",
		".CRT$XLA":      "First Loader TLS Callback",
		".CRT$XLC":      "CRT TLS Constructor",
		".CRT$XLD":      "CRT TLS Terminator",
		".CRT$XLZ":      "Last Loader TLS Callback",
		".CRT$XPA":      "First Pre-Terminator",
		".CRT$XPB":      "CRT ConcRT Pre-Terminator",
		".CRT$XPX":      "CRT Pre-Terminators",
		".CRT$XPXA":     "CRT stdio Pre-Terminator",
		".CRT$XPZ":      "Last Pre-Terminator",
		".CRT$XTA":      "First Terminator",
		".CRT$XTZ":      "Last Terminator",
		".CRTMA$XCA":    "First Managed C++ Initializer",
		".CRTMA$XCZ":    "Last Managed C++ Initializer",
		".CRTVT$XCA":    "First Managed VTable Initializer",
		".CRTVT$XCZ":    "Last Managed VTable Initializer",
		".rtc$IAA":      "First RTC Initializer",
		".rtc$IZZ":      "Last RTC Initializer",
		".rtc$TAA":      "First RTC Terminator",
		".rtc$TZZ":      "Last RTC Terminator",
		".text$x":       "EH Filters",
		".text$di":      "MSVC Dynamic Initializers",
		".text$yd":      "MSVC Destructors",
		".text$mn":      "Contains EP",
		".00cfg":        "CFG Check Functions Pointers",
		".rdata$T":      "TLS Header",
		".rdata$r":      "RTTI Data",
		".data$r":       "RTTI Type Descriptors",
		".rdata$sxdata": "Safe SEH",
		".rdata$zzzdbg": "Debug Data",
		".idata$2":      "Import Descriptors",
		".idata$3":      "Final Null Entry",
		".idata$4":      "INT Array",
		".idata$5":      "IAT Array",
		".idata$6":      "Symbol and DLL names",
		".rsrc$01":      "Resources Header",
		".rsrc$02":      "Resources Data",
	}

	if val, ok := sectionNameMap[section]; ok {
		return val
	}

	return "?"
}

// FPOFrameTypePretty returns a string interpretation of the FPO frame type.
func FPOFrameTypePretty(ft uint8) string {
	frameTypeMap := map[uint8]string{
		FrameFPO:    "FPO",
		FrameTrap:   "Trap",
		FrameTSS:    "TSS",
		FrameNonFPO: "NonFPO",
	}

	v, ok := frameTypeMap[ft]
	if ok {
		return v
	}

	return "?"
}

// PrettyExtendedDLLCharacteristics maps DLL char to string.
func PrettyExtendedDLLCharacteristics(characteristics uint32) []string {

	var values []string

	exDllCharacteristicsMap := map[uint32]string{
		ImageDllCharacteristicsExCETCompat: "CET Compatible",
	}
	for k, s := range exDllCharacteristicsMap {
		if k&characteristics != 0 {
			values = append(values, s)
		}
	}

	return values
}

// String returns the string representation of a GUID.
func (g GUID) String() string {
	return fmt.Sprintf("{%06X-%04X-%04X-%04X-%X}", g.Data1, g.Data2, g.Data3, g.Data4[0:2], g.Data4[2:])
}

// String returns the string representation of a debug entry.
func (de DebugEntry) String() string {
	switch de.Struct.Type {
	case ImageDebugTypeCodeView:
		return "CodeView"
	case ImageDebugTypePOGO:
		return "PGP"
	case ImageDebugTypeFPO:
		return "FPO"
	case ImageDebugTypeRepro:
		return "REPRO"
	case ImageDebugTypeVCFeature:
		return "VC Feature"
	case ImageDebugTypeExDllCharacteristics:
		return "Ex.DLL Characteristics"
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

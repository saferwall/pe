// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

// ImageFileHeaderMachineType represents the type of the image file header `Machine“ field.
type ImageFileHeaderMachineType uint16

// ImageFileHeaderCharacteristicsType represents the type of the image file header
// `Characteristics` field.
type ImageFileHeaderCharacteristicsType uint16

// ImageOptionalHeaderSubsystemType represents the type of the optional header `Subsystem field.
type ImageOptionalHeaderSubsystemType uint16

// ImageOptionalHeaderDllCharacteristicsType represents the type of the optional header `DllCharacteristics field.
type ImageOptionalHeaderDllCharacteristicsType uint16

// ImageNtHeader represents the PE header and is the general term for a structure
// named IMAGE_NT_HEADERS.
type ImageNtHeader struct {
	// Signature is a DWORD containing the value 50h, 45h, 00h, 00h.
	Signature uint32 `json:"signature"`

	// IMAGE_NT_HEADERS provides a standard COFF header. It is located
	// immediately after the PE signature. The COFF header provides the most
	// general characteristics of a PE/COFF file, applicable to both object and
	// executable files. It is represented with IMAGE_FILE_HEADER structure.
	FileHeader ImageFileHeader `json:"file_header"`

	// OptionalHeader is of type *OptionalHeader32 or *OptionalHeader64.
	OptionalHeader interface{} `json:"optional_header"`
}

// ImageFileHeader contains infos about the physical layout and properties of the
// file.
type ImageFileHeader struct {
	// The number that identifies the type of target machine.
	Machine ImageFileHeaderMachineType `json:"machine"`

	// The number of sections. This indicates the size of the section table,
	// which immediately follows the headers.
	NumberOfSections uint16 `json:"number_of_sections"`

	// // The low 32 bits of the number of seconds since 00:00 January 1, 1970
	// (a C run-time time_t value), that indicates when the file was created.
	TimeDateStamp uint32 `json:"time_date_stamp"`

	// // The file offset of the COFF symbol table, or zero if no COFF symbol
	// table is present. This value should be zero for an image because COFF
	// debugging information is deprecated.
	PointerToSymbolTable uint32 `json:"pointer_to_symbol_table"`

	// The number of entries in the symbol table. This data can be used to
	// locate the string table, which immediately follows the symbol table.
	// This value should be zero for an image because COFF debugging information
	// is deprecated.
	NumberOfSymbols uint32 `json:"number_of_symbols"`

	// The size of the optional header, which is required for executable files
	// but not for object files. This value should be zero for an object file.
	SizeOfOptionalHeader uint16 `json:"size_of_optional_header"`

	// The flags that indicate the attributes of the file.
	Characteristics ImageFileHeaderCharacteristicsType `json:"characteristics"`
}

// ImageOptionalHeader32 represents the PE32 format structure of the optional header.
// PE32 contains this additional field, which is absent in PE32+.
type ImageOptionalHeader32 struct {

	// The unsigned integer that identifies the state of the image file.
	// The most common number is 0x10B, which identifies it as a normal
	// executable file. 0x107 identifies it as a ROM image, and 0x20B identifies
	// it as a PE32+ executable.
	Magic uint16 `json:"magic"`

	// Linker major version number. The VC++ linker sets this field to current
	// version of Visual Studio.
	MajorLinkerVersion uint8 `json:"major_linker_version"`

	// The linker minor version number.
	MinorLinkerVersion uint8 `json:"minor_linker_version"`

	// The size of the code (text) section, or the sum of all code sections
	// if there are multiple sections.
	SizeOfCode uint32 `json:"size_of_code"`

	// The size of the initialized data section (held in the field SizeOfRawData
	// of the respective section header), or the sum of all such sections if
	// there are multiple data sections.
	SizeOfInitializedData uint32 `json:"size_of_initialized_data"`

	// The size of the uninitialized data section (BSS), or the sum of all
	// such sections if there are multiple BSS sections. This data is not part
	// of the disk file and does not have specific values, but the OS loader
	// commits memory space for this data when the file is loaded.
	SizeOfUninitializedData uint32 `json:"size_of_uninitialized_data"`

	// The address of the entry point relative to the image base when the
	// executable file is loaded into memory. For program images, this is the
	// starting address. For device drivers, this is the address of the
	// initialization function. An entry point is optional for DLLs. When no
	// entry point is present, this field must be zero. For managed PE files,
	// this value always points to the common language runtime invocation stub.
	AddressOfEntryPoint uint32 `json:"address_of_entrypoint"`

	// The address that is relative to the image base of the beginning-of-code
	// section when it is loaded into memory.
	BaseOfCode uint32 `json:"base_of_code"`

	// The address that is relative to the image base of the beginning-of-data
	// section when it is loaded into memory. This entry doesn’t exist in the
	// 64-bit Optional header.
	BaseOfData uint32 `json:"base_of_data"`

	// The preferred address of the first byte of image when loaded into memory;
	// must be a multiple of 64 K. The default for DLLs is 0x10000000. The
	// default for Windows CE EXEs is 0x00010000. The default for Windows NT,
	// Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is
	// 0x00400000.
	ImageBase uint32 `json:"image_base"`

	// The alignment (in bytes) of sections when they are loaded into memory.
	// It must be greater than or equal to FileAlignment. The default is the
	// page size for the architecture.
	SectionAlignment uint32 `json:"section_alignment"`

	// The alignment factor (in bytes) that is used to align the raw data of
	// sections in the image file. The value should be a power of 2 between 512
	// and 64 K, inclusive. The default is 512. If the SectionAlignment is less
	// than the architecture's page size, then FileAlignment must match
	// SectionAlignment.
	FileAlignment uint32 `json:"file_alignment"`

	// The major version number of the required operating system.
	MajorOperatingSystemVersion uint16 `json:"major_os_version"`

	// The minor version number of the required operating system.
	MinorOperatingSystemVersion uint16 `json:"minor_os_version"`

	// The major version number of the image.
	MajorImageVersion uint16 `json:"major_image_version"`

	// The minor version number of the image.
	MinorImageVersion uint16 `json:"minor_image_version"`

	// The major version number of the subsystem.
	MajorSubsystemVersion uint16 `json:"major_subsystem_version"`

	// The minor version number of the subsystem.
	MinorSubsystemVersion uint16 `json:"minor_subsystem_version"`

	// Reserved, must be zero.
	Win32VersionValue uint32 `json:"win32_version_value"`

	// The size (in bytes) of the image, including all headers, as the image
	// is loaded in memory. It must be a multiple of SectionAlignment.
	SizeOfImage uint32 `json:"size_of_image"`

	// The combined size of an MS-DOS stub, PE header, and section headers
	// rounded up to a multiple of FileAlignment.
	SizeOfHeaders uint32 `json:"size_of_headers"`

	// The image file checksum. The algorithm for computing the checksum is
	// incorporated into IMAGHELP.DLL. The following are checked for validation
	// at load time: all drivers, any DLL loaded at boot time, and any DLL
	// that is loaded into a critical Windows process.
	CheckSum uint32 `json:"checksum"`

	// The subsystem that is required to run this image.
	Subsystem ImageOptionalHeaderSubsystemType `json:"subsystem"`

	// For more information, see DLL Characteristics later in this specification.
	DllCharacteristics ImageOptionalHeaderDllCharacteristicsType `json:"dll_characteristics"`

	// Size of virtual memory to reserve for the initial thread’s stack. Only
	// the SizeOfStackCommit field is committed; the rest is available in
	// one-page increments. The default is 1MB for 32-bit images and 4MB for
	// 64-bit images.
	SizeOfStackReserve uint32 `json:"size_of_stack_reserve"`

	// Size of virtual memory initially committed for the initial thread’s
	// stack. The default is one page (4KB) for 32-bit images and 16KB for
	// 64-bit images.
	SizeOfStackCommit uint32 `json:"size_of_stack_commit"`

	// size of the local heap space to reserve. Only SizeOfHeapCommit is
	// committed; the rest is made available one page at a time until the
	// reserve size is reached. The default is 1MB for both 32-bit and 64-bit
	// images.
	SizeOfHeapReserve uint32 `json:"size_of_heap_reserve"`

	// Size of virtual memory initially committed for the process heap. The
	// default is 4KB (one operating system memory page) for 32-bit images and
	// 16KB for 64-bit images.
	SizeOfHeapCommit uint32 `json:"size_of_heap_commit"`

	// Reserved, must be zero.
	LoaderFlags uint32 `json:"loader_flags"`

	// Number of entries in the DataDirectory array; at least 16. Although it
	// is theoretically possible to emit more than 16 data directories, all
	// existing managed compilers emit exactly 16 data directories, with the
	// 16th (last) data directory never used (reserved).
	NumberOfRvaAndSizes uint32 `json:"number_of_rva_and_sizes"`

	// An array of 16 IMAGE_DATA_DIRECTORY structures.
	DataDirectory [16]DataDirectory `json:"data_directories"`
}

// ImageOptionalHeader64 represents the PE32+ format structure of the optional header.
type ImageOptionalHeader64 struct {
	// The unsigned integer that identifies the state of the image file.
	// The most common number is 0x10B, which identifies it as a normal
	// executable file. 0x107 identifies it as a ROM image, and 0x20B identifies
	// it as a PE32+ executable.
	Magic uint16 `json:"magic"`

	// Linker major version number. The VC++ linker sets this field to current
	// version of Visual Studio.
	MajorLinkerVersion uint8 `json:"major_linker_version"`

	// The linker minor version number.
	MinorLinkerVersion uint8 `json:"minor_linker_version"`

	// The size of the code (text) section, or the sum of all code sections
	// if there are multiple sections.
	SizeOfCode uint32 `json:"size_of_code"`

	// The size of the initialized data section (held in the field SizeOfRawData
	// of the respective section header), or the sum of all such sections if
	// there are multiple data sections.
	SizeOfInitializedData uint32 `json:"size_of_initialized_data"`

	// The size of the uninitialized data section (BSS), or the sum of all
	// such sections if there are multiple BSS sections. This data is not part
	// of the disk file and does not have specific values, but the OS loader
	// commits memory space for this data when the file is loaded.
	SizeOfUninitializedData uint32 `json:"size_of_uninitialized_data"`

	// The address of the entry point relative to the image base when the
	// executable file is loaded into memory. For program images, this is the
	// starting address. For device drivers, this is the address of the
	// initialization function. An entry point is optional for DLLs. When no
	// entry point is present, this field must be zero. For managed PE files,
	// this value always points to the common language runtime invocation stub.
	AddressOfEntryPoint uint32 `json:"address_of_entrypoint"`

	// The address that is relative to the image base of the beginning-of-code
	// section when it is loaded into memory.
	BaseOfCode uint32 `json:"base_of_code"`

	// In PE+, ImageBase is 8 bytes size.
	ImageBase uint64 `json:"image_base"`

	// The alignment (in bytes) of sections when they are loaded into memory.
	// It must be greater than or equal to FileAlignment. The default is the
	// page size for the architecture.
	SectionAlignment uint32 `json:"section_alignment"`

	// The alignment factor (in bytes) that is used to align the raw data of
	// sections in the image file. The value should be a power of 2 between 512
	// and 64 K, inclusive. The default is 512. If the SectionAlignment is less
	// than the architecture's page size, then FileAlignment must match SectionAlignment.
	FileAlignment uint32 `json:"file_alignment"`

	// The major version number of the required operating system.
	MajorOperatingSystemVersion uint16 `json:"major_os_version"`

	// The minor version number of the required operating system.
	MinorOperatingSystemVersion uint16 `json:"minor_os_version"`

	// The major version number of the image.
	MajorImageVersion uint16 `json:"major_image_version"`

	// The minor version number of the image.
	MinorImageVersion uint16 `json:"minor_image_version"`

	// The major version number of the subsystem.
	MajorSubsystemVersion uint16 `json:"major_subsystem_version"`

	// The minor version number of the subsystem.
	MinorSubsystemVersion uint16 `json:"minor_subsystem_version"`

	// Reserved, must be zero.
	Win32VersionValue uint32 `json:"win32_version_value"`

	// The size (in bytes) of the image, including all headers, as the image
	// is loaded in memory. It must be a multiple of SectionAlignment.
	SizeOfImage uint32 `json:"size_of_image"`

	// The combined size of an MS-DOS stub, PE header, and section headers
	// rounded up to a multiple of FileAlignment.
	SizeOfHeaders uint32 `json:"size_of_headers"`

	// The image file checksum. The algorithm for computing the checksum is
	// incorporated into IMAGHELP.DLL. The following are checked for validation
	// at load time: all drivers, any DLL loaded at boot time, and any DLL
	// that is loaded into a critical Windows process.
	CheckSum uint32 `json:"checksum"`

	// The subsystem that is required to run this image.
	Subsystem ImageOptionalHeaderSubsystemType `json:"subsystem"`

	// For more information, see DLL Characteristics later in this specification.
	DllCharacteristics ImageOptionalHeaderDllCharacteristicsType `json:"dll_characteristics"`

	// Size of virtual memory to reserve for the initial thread’s stack. Only
	// the SizeOfStackCommit field is committed; the rest is available in
	// one-page increments. The default is 1MB for 32-bit images and 4MB for
	// 64-bit images.
	SizeOfStackReserve uint64 `json:"size_of_stack_reserve"`

	// Size of virtual memory initially committed for the initial thread’s
	// stack. The default is one page (4KB) for 32-bit images and 16KB for
	// 64-bit images.
	SizeOfStackCommit uint64 `json:"size_of_stack_commit"`

	// size of the local heap space to reserve. Only SizeOfHeapCommit is
	// committed; the rest is made available one page at a time until the
	// reserve size is reached. The default is 1MB for both 32-bit and 64-bit
	// images.
	SizeOfHeapReserve uint64 `json:"size_of_heap_reserve"`

	// Size of virtual memory initially committed for the process heap. The
	// default is 4KB (one operating system memory page) for 32-bit images and
	// 16KB for 64-bit images.
	SizeOfHeapCommit uint64 `json:"size_of_heap_commit"`

	// Reserved, must be zero.
	LoaderFlags uint32 `json:"loader_flags"`

	// Number of entries in the DataDirectory array; at least 16. Although it
	// is theoretically possible to emit more than 16 data directories, all
	// existing managed compilers emit exactly 16 data directories, with the
	// 16th (last) data directory never used (reserved).
	NumberOfRvaAndSizes uint32 `json:"number_of_rva_and_sizes"`

	// An array of 16 IMAGE_DATA_DIRECTORY structures.
	DataDirectory [16]DataDirectory `json:"data_directories"`
}

// DataDirectory represents an array of 16 IMAGE_DATA_DIRECTORY structures,
// 8 bytes apiece, each relating to an important data structure in the PE file.
// The data directory table starts at offset 96 in a 32-bit PE header and at
// offset 112 in a 64-bit PE header. Each entry in the data directory table
// contains the RVA and size of a table or a string that this particular
// directory entry describes;this information is used by the operating system.
type DataDirectory struct {
	VirtualAddress uint32 // The RVA of the data structure.
	Size           uint32 // The size in bytes of the data structure referred to.
}

// ParseNTHeader parse the PE NT header structure referred as IMAGE_NT_HEADERS.
// Its offset is given by the e_lfanew field in the IMAGE_DOS_HEADER at the
// beginning of the file.
func (pe *File) ParseNTHeader() (err error) {
	ntHeaderOffset := pe.DOSHeader.AddressOfNewEXEHeader
	signature, err := pe.ReadUint32(ntHeaderOffset)
	if err != nil {
		return ErrInvalidNtHeaderOffset
	}

	// Probe for PE signature.
	if signature&0xFFFF == ImageOS2Signature {
		return ErrImageOS2SignatureFound
	}
	if signature&0xFFFF == ImageOS2LESignature {
		return ErrImageOS2LESignatureFound
	}
	if signature&0xFFFF == ImageVXDSignature {
		return ErrImageVXDSignatureFound
	}
	if signature&0xFFFF == ImageTESignature {
		return ErrImageTESignatureFound
	}

	// This is the smallest requirement for a valid PE.
	if signature != ImageNTSignature {
		return ErrImageNtSignatureNotFound
	}
	pe.NtHeader.Signature = signature

	// The file header structure contains some basic information about the file;
	// most importantly, a field describing the size of the optional data that
	// follows it.
	fileHeaderSize := uint32(binary.Size(pe.NtHeader.FileHeader))
	fileHeaderOffset := ntHeaderOffset + 4
	err = pe.structUnpack(&pe.NtHeader.FileHeader, fileHeaderOffset, fileHeaderSize)
	if err != nil {
		return err
	}

	// The PE header which immediately follows the COFF header, provides
	// information for the OS loader. Although this header is referred to as
	// the optional header, it is optional only in the sense that object files
	// usually don’t contain it. For PE files, this header is mandatory.
	// The size of the PE header is not fixed. It depends on the number of data
	// directories defined in the header and is specified in the
	// SizeOfOptionalHeader field of the COFF header.
	// The optional header could be either for a PE or PE+ file.
	oh32 := ImageOptionalHeader32{}
	oh64 := ImageOptionalHeader64{}

	optHeaderOffset := ntHeaderOffset + (fileHeaderSize + 4)
	magic, err := pe.ReadUint16(optHeaderOffset)
	if err != nil {
		return err
	}

	// Probes for PE32/PE32+ optional header magic.
	if magic != ImageNtOptionalHeader32Magic &&
		magic != ImageNtOptionalHeader64Magic {
		return ErrImageNtOptionalHeaderMagicNotFound
	}

	// Are we dealing with a PE64 optional header.
	switch magic {
	case ImageNtOptionalHeader64Magic:
		size := uint32(binary.Size(oh64))
		err = pe.structUnpack(&oh64, optHeaderOffset, size)
		if err != nil {
			return err
		}
		pe.Is64 = true
		pe.NtHeader.OptionalHeader = oh64
	case ImageNtOptionalHeader32Magic:
		size := uint32(binary.Size(oh32))
		err = pe.structUnpack(&oh32, optHeaderOffset, size)
		if err != nil {
			return err
		}
		pe.Is32 = true
		pe.NtHeader.OptionalHeader = oh32
	}

	// ImageBase should be multiple of 10000h.
	if (pe.Is64 && oh64.ImageBase%0x10000 != 0) || (pe.Is32 && oh32.ImageBase%0x10000 != 0) {
		return ErrImageBaseNotAligned
	}

	// ImageBase can be any value as long as:
	// ImageBase + SizeOfImage < 80000000h for PE32.
	// ImageBase + SizeOfImage < 0xffff080000000000 for PE32+.
	if (pe.Is32 && oh32.ImageBase+oh32.SizeOfImage >= 0x80000000) || (pe.Is64 && oh64.ImageBase+uint64(oh64.SizeOfImage) >= 0xffff080000000000) {
		pe.Anomalies = append(pe.Anomalies, AnoImageBaseOverflow)
	}

	pe.HasNTHdr = true
	return nil
}

// String returns the string representations of the `Machine` field of the IMAGE_FILE_HEADER.
func (t ImageFileHeaderMachineType) String() string {
	machineType := map[ImageFileHeaderMachineType]string{
		ImageFileMachineUnknown:   "Unknown",
		ImageFileMachineAM33:      "Matsushita AM33",
		ImageFileMachineAMD64:     "x64",
		ImageFileMachineARM:       "ARM little endian",
		ImageFileMachineARM64:     "ARM64 little endian",
		ImageFileMachineARMNT:     "ARM Thumb-2 little endian",
		ImageFileMachineEBC:       "EFI byte code",
		ImageFileMachineI386:      "Intel 386 or later / compatible processors",
		ImageFileMachineIA64:      "Intel Itanium processor family",
		ImageFileMachineM32R:      "Mitsubishi M32R little endian",
		ImageFileMachineMIPS16:    "MIPS16",
		ImageFileMachineMIPSFPU:   "MIPS with FPU",
		ImageFileMachineMIPSFPU16: "MIPS16 with FPU",
		ImageFileMachinePowerPC:   "Power PC little endian",
		ImageFileMachinePowerPCFP: "Power PC with floating point support",
		ImageFileMachineR4000:     "MIPS little endian",
		ImageFileMachineRISCV32:   "RISC-V 32-bit address space",
		ImageFileMachineRISCV64:   "RISC-V 64-bit address space",
		ImageFileMachineRISCV128:  "RISC-V 128-bit address space",
		ImageFileMachineSH3:       "Hitachi SH3",
		ImageFileMachineSH3DSP:    "Hitachi SH3 DSP",
		ImageFileMachineSH4:       "Hitachi SH4",
		ImageFileMachineSH5:       "Hitachi SH5",
		ImageFileMachineTHUMB:     "Thumb",
		ImageFileMachineWCEMIPSv2: "MIPS little-endian WCE v2",
	}

	if val, ok := machineType[t]; ok {
		return val
	}
	return "?"
}

// String returns the string representations of the `Characteristics` field of the IMAGE_FILE_HEADER.
func (t ImageFileHeaderCharacteristicsType) String() []string {
	var values []string
	fileHeaderCharacteristics := map[ImageFileHeaderCharacteristicsType]string{
		ImageFileRelocsStripped:       "RelocsStripped",
		ImageFileExecutableImage:      "ExecutableImage",
		ImageFileLineNumsStripped:     "LineNumsStripped",
		ImageFileLocalSymsStripped:    "LocalSymsStripped",
		ImageFileAggressiveWSTrim:     "AgressibeWsTrim",
		ImageFileLargeAddressAware:    "LargeAddressAware",
		ImageFileBytesReservedLow:     "BytesReservedLow",
		ImageFile32BitMachine:         "32BitMachine",
		ImageFileDebugStripped:        "DebugStripped",
		ImageFileRemovableRunFromSwap: "RemovableRunFromSwap",
		ImageFileSystem:               "FileSystem",
		ImageFileDLL:                  "DLL",
		ImageFileUpSystemOnly:         "UpSystemOnly",
		ImageFileBytesReservedHigh:    "BytesReservedHigh",
	}

	for k, s := range fileHeaderCharacteristics {
		if k&t != 0 {
			values = append(values, s)
		}
	}

	return values
}

// String returns the string representations of the `DllCharacteristics` field of ImageOptionalHeader.
func (t ImageOptionalHeaderDllCharacteristicsType) String() []string {
	var values []string

	imgDllCharacteristics := map[ImageOptionalHeaderDllCharacteristicsType]string{
		ImageDllCharacteristicsHighEntropyVA:        "HighEntropyVA",
		ImageDllCharacteristicsDynamicBase:          "DynamicBase",
		ImageDllCharacteristicsForceIntegrity:       "ForceIntegrity",
		ImageDllCharacteristicsNXCompact:            "NXCompact",
		ImageDllCharacteristicsNoIsolation:          "NoIsolation",
		ImageDllCharacteristicsNoSEH:                "NoSEH",
		ImageDllCharacteristicsNoBind:               "NoBind",
		ImageDllCharacteristicsAppContainer:         "AppContainer",
		ImageDllCharacteristicsWdmDriver:            "WdmDriver",
		ImageDllCharacteristicsGuardCF:              "GuardCF",
		ImageDllCharacteristicsTerminalServiceAware: "TerminalServiceAware",
	}

	for k, s := range imgDllCharacteristics {
		if k&t != 0 {
			values = append(values, s)
		}
	}

	return values
}

// String returns the string representations of the `Subsystem` field
// of ImageOptionalHeader.
func (subsystem ImageOptionalHeaderSubsystemType) String() string {
	subsystemMap := map[ImageOptionalHeaderSubsystemType]string{
		ImageSubsystemUnknown:                "Unknown",
		ImageSubsystemNative:                 "Native",
		ImageSubsystemWindowsGUI:             "Windows GUI",
		ImageSubsystemWindowsCUI:             "Windows CUI",
		ImageSubsystemOS2CUI:                 "OS/2 character",
		ImageSubsystemPosixCUI:               "POSIX character",
		ImageSubsystemNativeWindows:          "Native Win9x driver",
		ImageSubsystemWindowsCEGUI:           "Windows CE GUI",
		ImageSubsystemEFIApplication:         "EFI Application",
		ImageSubsystemEFIBootServiceDriver:   "EFI Boot Service Driver",
		ImageSubsystemEFIRuntimeDriver:       "EFI ROM image",
		ImageSubsystemEFIRom:                 "EFI ROM image",
		ImageSubsystemXBOX:                   "XBOX",
		ImageSubsystemWindowsBootApplication: "Windows boot application",
	}

	if val, ok := subsystemMap[subsystem]; ok {
		return val
	}

	return "?"
}

// PrettyOptionalHeaderMagic returns the string representations of the
// `Magic` field of ImageOptionalHeader.
func (pe *File) PrettyOptionalHeaderMagic() string {

	var magic uint16

	if pe.Is64 {
		magic =
			pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).Magic
	} else {
		magic =
			pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).Magic
	}

	switch magic {
	case ImageNtOptionalHeader32Magic:
		return "PE32"
	case ImageNtOptionalHeader64Magic:
		return "PE64"
	case ImageROMOptionalHeaderMagic:
		return "ROM"
	default:
		return "?"
	}
}

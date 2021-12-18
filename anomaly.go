// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"time"
)

// Anomalies found in a PE
var (

	// AnoPEHeaderOverlapDOSHeader is reported when the PE headers overlaps with the DOS header.
	AnoPEHeaderOverlapDOSHeader = "PE Header overlaps with DOS header"

	// AnoPETimeStampNull is reported when the file header timestamp is 0.
	AnoPETimeStampNull = "File Header timestamp set to 0"

	// AnoPETimeStampFuture is reported when the file header timestamp is more
	// than one day ahead of the current date timestamp.
	AnoPETimeStampFuture = "File Header timestamp set to 0"

	// NumberOfSections is reported when number of sections is larger or equal than 10.
	AnoNumberOfSections10Plus = "Number of sections is 10+"

	// AnoNumberOfSectionsNull is reported when sections count's is 0.
	AnoNumberOfSectionsNull = "Number of sections is 0"

	// AnoSizeOfOptionalHeaderNull is reported when size of optional header is 0.
	AnoSizeOfOptionalHeaderNull = "Size of optional header is 0"

	// AnoUncommonSizeOfOptionalHeader32 is reported when size of optional
	// header for PE32 is larger than 0xE0.
	AnoUncommonSizeOfOptionalHeader32 = "Size of optional header is larger than 0xE0 (PE32)"

	// AnoUncommonSizeOfOptionalHeader64 is reported when size of optional
	// header for PE32+ is larger than 0xF0.
	AnoUncommonSizeOfOptionalHeader64 = "Size of optional header is larger than 0xF0 (PE32+)"

	// AnoAddressOfEntryPointNull is reported when address of entry point is 0.
	AnoAddressOfEntryPointNull = "Address of entry point is 0"

	// AnoAddressOfEPLessSizeOfHeaders is reported when address of entry point
	// is smaller than size of headers, the file cannot run under Windows.
	AnoAddressOfEPLessSizeOfHeaders = "Address of entry point is smaller than size of headers, " +
		"the file cannot run under Windows 8"

	// AnoImageBaseNull is reported when the image base is null.
	AnoImageBaseNull = "Image base is 0"

	// AnoDanSMagicOffset is reported when the `DanS` magic offset is different than 0x80.
	AnoDanSMagicOffset = "`DanS` magic offset is different than 0x80"

	// ErrInvalidFileAlignment is reported when file alignment is larger than
	//  0x200 and not a power of 2.
	ErrInvalidFileAlignment = "FileAlignment larger than 0x200 and not a power of 2"

	// ErrInvalidSectionAlignment is reported when file alignment is lesser
	// than 0x200 and different from section alignment.
	ErrInvalidSectionAlignment = "FileAlignment lesser than 0x200 and different from section alignment"

	// AnoMajorSubsystemVersion is reported when MajorSubsystemVersion has a
	// value different than the standard 3 --> 6.
	AnoMajorSubsystemVersion = "MajorSubsystemVersion is outside 3<-->6 boundary"

	// AnonWin32VersionValue is reported when Win32VersionValue is different than 0
	AnonWin32VersionValue = "Win32VersionValue is a reserved field, must be set to zero"

	// AnoInvalidPEChecksum is reported when the optional header checksum field
	// is different from what it should normally be.
	AnoInvalidPEChecksum = "Optional header checksum is invalid"

	// AnoNumberOfRvaAndSizes is reported when NumberOfRvaAndSizes is different than 16.
	AnoNumberOfRvaAndSizes = "Optional header NumberOfRvaAndSizes != 16"

	// AnoReservedDataDirectoryEntry is reported when the last data directory entry is not zero.
	AnoReservedDataDirectoryEntry = "Last data directory entry is a reserved field, must be set to zero"

	// AnoNumberOfRvaAndSizes is reported when number of COFF symbols is absurdly high.
	AnoCOFFSymbolsCount = "COFF symbols count is absurdly high"
)

// GetAnomalies reportes anomalies found in a PE binary.
// These nomalies does prevent the Windows loader from loading the files but
// is an interesting features for malware analysis.
func (pe *File) GetAnomalies() error {

	// ******************** Anomalies in File header ************************
	// An application for Windows NT typically has the nine predefined sections
	// named: .text, .bss, .rdata, .data, .rsrc, .edata, .idata, .pdata, and
	// .debug. Some applications do not need all of these sections, while
	// others may define still more sections to suit their specific needs.
	// NumberOfSections can be up to 96 under XP.
	// NumberOfSections can be up to 65535 under Vista and later.
	if pe.NtHeader.FileHeader.NumberOfSections >= 10 {
		pe.Anomalies = append(pe.Anomalies, AnoNumberOfSections10Plus)
	}

	// File header timestamp set to 0.
	if pe.NtHeader.FileHeader.TimeDateStamp == 0 {
		pe.Anomalies = append(pe.Anomalies, AnoPETimeStampNull)
	}

	// File header timestamp set to the future.
	now := time.Now()
	future := uint32(now.Add(24 * time.Hour).Unix())
	if pe.NtHeader.FileHeader.TimeDateStamp > future {
		pe.Anomalies = append(pe.Anomalies, AnoPETimeStampFuture)
	}

	// NumberOfSections can be null with low alignment PEs
	// and in this case, the values are just checked but not really used (under XP)
	if pe.NtHeader.FileHeader.NumberOfSections == 0 {
		pe.Anomalies = append(pe.Anomalies, AnoNumberOfSectionsNull)
	}

	// SizeOfOptionalHeader is not the size of the optional header, but the delta
	// between the top of the Optional header and the start of the section table.
	// Thus, it can be null (the section table will overlap the Optional Header,
	// or can be null when no sections are present)
	if pe.NtHeader.FileHeader.SizeOfOptionalHeader == 0 {
		pe.Anomalies = append(pe.Anomalies, AnoSizeOfOptionalHeaderNull)
	}

	// SizeOfOptionalHeader can be bigger than the file
	// (the section table will be in virtual space, full of zeroes), but can't be negative.
	// Do some check here.
	oh32 := ImageOptionalHeader32{}
	oh64 := ImageOptionalHeader64{}

	// SizeOfOptionalHeader standard value is 0xE0 for PE32.
	if pe.Is32 &&
		pe.NtHeader.FileHeader.SizeOfOptionalHeader > uint16(binary.Size(oh32)) {
		pe.Anomalies = append(pe.Anomalies, AnoUncommonSizeOfOptionalHeader32)
	}

	// SizeOfOptionalHeader standard value is 0xF0 for PE32+.
	if pe.Is64 &&
		pe.NtHeader.FileHeader.SizeOfOptionalHeader > uint16(binary.Size(oh64)) {
		pe.Anomalies = append(pe.Anomalies, AnoUncommonSizeOfOptionalHeader64)
	}

	// ***************** Anomalies in Optional header *********************
	// Under Windows 8, AddressOfEntryPoint is not allowed to be smaller than
	// SizeOfHeaders, except if it's null.
	switch pe.Is64 {
	case true:
		oh64 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64)
	case false:
		oh32 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32)
	}

	// Use oh for fields which are common for both structures.
	oh := oh32
	if oh.AddressOfEntryPoint != 0 && oh.AddressOfEntryPoint < oh.SizeOfHeaders {
		pe.Anomalies = append(pe.Anomalies, AnoAddressOfEPLessSizeOfHeaders)
	}

	// AddressOfEntryPoint can be null in DLLs: in this case,
	// DllMain is just not called. can be null
	if oh.AddressOfEntryPoint == 0 {
		pe.Anomalies = append(pe.Anomalies, AnoAddressOfEntryPointNull)
	}

	// ImageBase can be null, under XP.
	// In this case, the binary will be relocated to 10000h
	if (pe.Is64 && oh64.ImageBase == 0) ||
		(pe.Is32 && oh32.ImageBase == 0) {
		pe.Anomalies = append(pe.Anomalies, AnoImageBaseNull)
	}

	// The msdn states that SizeOfImage must be a multiple of the section
	// alignment. This is not a requirement though. Adding it as anomaly.
	// Todo: raise an anomaly when SectionAlignment is NULL ?
	if oh.SectionAlignment != 0 && oh.SizeOfImage%oh.SectionAlignment != 0 {
		pe.Anomalies = append(pe.Anomalies, AnoInvalidSizeOfImage)
	}

	// For DLLs, MajorSubsystemVersion is ignored until Windows 8. It can have
	// any value. Under Windows 8, it needs a standard value (3.10 < 6.30).
	if oh.MajorSubsystemVersion < 3 || oh.MajorSubsystemVersion > 6 {
		pe.Anomalies = append(pe.Anomalies, AnoMajorSubsystemVersion)
	}

	// Win32VersionValue officially defined as `reserved` and should be null
	// if non null, it overrides MajorVersion/MinorVersion/BuildNumber/PlatformId
	// OperatingSystem Versions values located in the PEB, after loading.
	if oh.Win32VersionValue != 0 {
		pe.Anomalies = append(pe.Anomalies, AnonWin32VersionValue)
	}

	// Checksums are required for kernel-mode drivers and some system DLLs.
	// Otherwise, this field can be 0.
	if pe.Checksum() != oh.CheckSum && oh.CheckSum != 0 {
		pe.Anomalies = append(pe.Anomalies, AnoInvalidPEChecksum)
	}

	// This field contains the number of IMAGE_DATA_DIRECTORY entries.
	//  This field has been 16 since the earliest releases of Windows NT.
	if (pe.Is64 && oh64.NumberOfRvaAndSizes == 0xA) ||
		(pe.Is32 && oh32.NumberOfRvaAndSizes == 0xA) {
		pe.Anomalies = append(pe.Anomalies, AnoNumberOfRvaAndSizes)
	}

	return nil
}

// addAnomaly appends the given anomaly to the list of anomalies.
func (pe *File) addAnomaly(anomaly string) {
	if !stringInSlice(anomaly, pe.Anomalies) {
		pe.Anomalies = append(pe.Anomalies, anomaly)
	}
}

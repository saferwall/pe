// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"math"
	"sort"
	"strings"
)

const (
	// ImageSectionReserved1 for future use.
	ImageSectionReserved1 = 0x00000000

	// ImageSectionReserved2 for future use.
	ImageSectionReserved2 = 0x00000001

	// ImageSectionReserved3 for future use.
	ImageSectionReserved3 = 0x00000002

	// ImageSectionReserved4 for future use.
	ImageSectionReserved4 = 0x00000004

	// ImageSectionTypeNoPad indicates the section should not be padded to the next
	// boundary. This flag is obsolete and is replaced by ImageSectionAlign1Bytes.
	// This is valid only for object files.
	ImageSectionTypeNoPad = 0x00000008

	// ImageSectionReserved5 for future use.
	ImageSectionReserved5 = 0x00000010

	// ImageSectionCntCode indicates the section contains executable code.
	ImageSectionCntCode = 0x00000020

	// ImageSectionCntInitializedData indicates the section contains initialized
	// data.
	ImageSectionCntInitializedData = 0x00000040

	// ImageSectionCntUninitializedData indicates the section contains uninitialized
	// data.
	ImageSectionCntUninitializedData = 0x00000080

	// ImageSectionLnkOther is reserved for future use.
	ImageSectionLnkOther = 0x00000100

	// ImageSectionLnkInfo indicates the section contains comments or other
	// information. The .drectve section has this type. This is valid for
	// object files only.
	ImageSectionLnkInfo = 0x00000200

	// ImageSectionReserved6 for future use.
	ImageSectionReserved6 = 0x00000400

	// ImageSectionLnkRemove indicates the section will not become part of the image
	// This is valid only for object files.
	ImageSectionLnkRemove = 0x00000800

	// ImageSectionLnkComdat indicates the section contains COMDAT data. For more
	// information, see COMDAT Sections (Object Only). This is valid only for
	// object files.
	ImageSectionLnkCOMDAT = 0x00001000

	// ImageSectionGpRel indicates the section contains data referenced through the
	// global pointer (GP).
	ImageSectionGpRel = 0x00008000

	// ImageSectionMemPurgeable is reserved for future use.
	ImageSectionMemPurgeable = 0x00020000

	// ImageSectionMem16Bit is reserved for future use.
	ImageSectionMem16Bit = 0x00020000

	// ImageSectionMemLocked is reserved for future use.
	ImageSectionMemLocked = 0x00040000

	// ImageSectionMemPreload is reserved for future use.
	ImageSectionMemPreload = 0x00080000

	// ImageSectionAlign1Bytes indicates to align data on a 1-byte boundary.
	// Valid only for object files.
	ImageSectionAlign1Bytes = 0x00100000

	// ImageSectionAlign2Bytes indicates to align data on a 2-byte boundary.
	// Valid only for object files.
	ImageSectionAlign2Bytes = 0x00200000

	// ImageSectionAlign4Bytes indicates to align data on a 4-byte boundary.
	// Valid only for object files.
	ImageSectionAlign4Bytes = 0x00300000

	// ImageSectionAlign8Bytes indicates to align data on a 8-byte boundary.
	// Valid only for object files.
	ImageSectionAlign8Bytes = 0x00400000

	// ImageSectionAlign16Bytes indicates to align data on a 16-byte boundary.
	// Valid only for object files.
	ImageSectionAlign16Bytes = 0x00500000

	// ImageSectionAlign32Bytes indicates to align data on a 32-byte boundary.
	// Valid only for object files.
	ImageSectionAlign32Bytes = 0x00600000

	// ImageSectionAlign64Bytes indicates to align data on a 64-byte boundary.
	// Valid only for object files.
	ImageSectionAlign64Bytes = 0x00700000

	// ImageSectionAlign128Bytes indicates to align data on a 128-byte boundary.
	// Valid only for object files.
	ImageSectionAlign128Bytes = 0x00800000

	// ImageSectionAlign256Bytes indicates to align data on a 256-byte boundary.
	// Valid only for object files.
	ImageSectionAlign256Bytes = 0x00900000

	// ImageSectionAlign512Bytes indicates to align data on a 512-byte boundary.
	// Valid only for object files.
	ImageSectionAlign512Bytes = 0x00A00000

	// ImageSectionAlign1024Bytes indicates to align data on a 1024-byte boundary.
	// Valid only for object files.
	ImageSectionAlign1024Bytes = 0x00B00000

	// ImageSectionAlign2048Bytes indicates to align data on a 2048-byte boundary.
	// Valid only for object files.
	ImageSectionAlign2048Bytes = 0x00C00000

	// ImageSectionAlign4096Bytes indicates to align data on a 4096-byte boundary.
	// Valid only for object files.
	ImageSectionAlign4096Bytes = 0x00D00000

	// ImageSectionAlign8192Bytes indicates to align data on a 8192-byte boundary.
	// Valid only for object files.
	ImageSectionAlign8192Bytes = 0x00E00000

	// ImageSectionLnkMRelocOvfl indicates the section contains extended
	// relocations.
	ImageSectionLnkMRelocOvfl = 0x01000000

	// ImageSectionMemDiscardable indicates the section can be discarded as needed.
	ImageSectionMemDiscardable = 0x02000000

	// ImageSectionMemNotCached indicates the  section cannot be cached.
	ImageSectionMemNotCached = 0x04000000

	// ImageSectionMemNotPaged indicates the section is not pageable.
	ImageSectionMemNotPaged = 0x08000000

	// ImageSectionMemShared indicates the section can be shared in memory.
	ImageSectionMemShared = 0x10000000

	// ImageSectionMemExecute indicates the section can be executed as code.
	ImageSectionMemExecute = 0x20000000

	// ImageSectionMemRead indicates the section can be read.
	ImageSectionMemRead = 0x40000000

	// ImageSectionMemWrite indicates the section can be written to.
	ImageSectionMemWrite = 0x80000000
)

// ImageSectionHeader is part of the section table , in fact section table is an
// array of Image Section Header each contains information about one section of
// the whole file such as attribute,virtual offset. the array size is the number
// of sections in the file.
// Binary Spec : each struct is 40 byte and there is no padding .
type ImageSectionHeader struct {

	//  An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8
	// characters long, there is no terminating null. For longer names, this
	// field contains a slash (/) that is followed by an ASCII representation of
	// a decimal number that is an offset into the string table. Executable
	// images do not use a string table and do not support section names longer
	// than 8 characters. Long names in object files are truncated if they are
	// emitted to an executable file.
	Name [8]uint8 `json:"name"`

	// The total size of the section when loaded into memory. If this value is
	// greater than SizeOfRawData, the section is zero-padded. This field is
	// valid only for executable images and should be set to zero for object files.
	VirtualSize uint32 `json:"virtual_size"`

	// For executable images, the address of the first byte of the section
	// relative to the image base when the section is loaded into memory.
	// For object files, this field is the address of the first byte before
	// relocation is applied; for simplicity, compilers should set this to zero.
	// Otherwise, it is an arbitrary value that is subtracted from offsets during
	// relocation.
	VirtualAddress uint32 `json:"virtual_address"`

	// The size of the section (for object files) or the size of the initialized
	// data on disk (for image files). For executable images, this must be a
	// multiple of FileAlignment from the optional header. If this is less than
	// VirtualSize, the remainder of the section is zero-filled. Because the
	// SizeOfRawData field is rounded but the VirtualSize field is not, it is
	// possible for SizeOfRawData to be greater than VirtualSize as well. When
	// a section contains only uninitialized data, this field should be zero.
	SizeOfRawData uint32 `json:"size_of_raw_data"`

	// The file pointer to the first page of the section within the COFF file.
	// For executable images, this must be a multiple of FileAlignment from the
	// optional header. For object files, the value should be aligned on a
	// 4-byte boundary for best performance. When a section contains only
	// uninitialized data, this field should be zero.
	PointerToRawData uint32 `json:"pointer_to_raw_data"`

	// The file pointer to the beginning of relocation entries for the section.
	// This is set to zero for executable images or if there are no relocations.
	PointerToRelocations uint32 `json:"pointer_to_relocations"`

	// The file pointer to the beginning of line-number entries for the section.
	// This is set to zero if there are no COFF line numbers. This value should
	// be zero for an image because COFF debugging information is deprecated.
	PointerToLineNumbers uint32 `json:"pointer_to_line_numbers"`

	// The number of relocation entries for the section.
	// This is set to zero for executable images.
	NumberOfRelocations uint16 `json:"number_of_relocations"`

	// The number of line-number entries for the section. This value should be
	// zero for an image because COFF debugging information is deprecated.
	NumberOfLineNumbers uint16 `json:"number_of_line_numbers"`

	// The flags that describe the characteristics of the section.
	Characteristics uint32 `json:"characteristics"`
}

// Section represents a PE section header, plus additional data like entropy.
type Section struct {
	Header ImageSectionHeader `json:"header"`
	// Entropy represents the section entropy. This field is not always populated
	// depending on weather entropy calculation is enabled. The reason behind
	// using a float64 pointer instead of a float64 is to distinguish between
	// the case when the section entropy is equal to zero and the case when the
	// entropy is equal to nil - meaning that it was never calculated.
	Entropy *float64 `json:"entropy,omitempty"`
}

// ParseSectionHeader parses the PE section headers. Each row of the section
// table is, in effect, a section header. It must immediately follow the PE
// header.
func (pe *File) ParseSectionHeader() (err error) {

	// Get the first section offset.
	optionalHeaderOffset := pe.DOSHeader.AddressOfNewEXEHeader + 4 +
		uint32(binary.Size(pe.NtHeader.FileHeader))
	offset := optionalHeaderOffset +
		uint32(pe.NtHeader.FileHeader.SizeOfOptionalHeader)

	// Track invalid/suspicious values while parsing sections.
	maxErr := 3

	secHeader := ImageSectionHeader{}
	numberOfSections := pe.NtHeader.FileHeader.NumberOfSections
	secHeaderSize := uint32(binary.Size(secHeader))

	// The section header indexing in the table is one-based, with the order of
	// the sections defined by the linker. The sections follow one another
	// contiguously in the order defined by the section header table, with
	// starting RVAs aligned by the value of the SectionAlignment field of the
	// PE header.
	for i := uint16(0); i < numberOfSections; i++ {
		err := pe.structUnpack(&secHeader, offset, secHeaderSize)
		if err != nil {
			return err
		}

		if secEnd := int64(secHeader.PointerToRawData) + int64(secHeader.SizeOfRawData); secEnd > pe.OverlayOffset {
			pe.OverlayOffset = secEnd
		}

		countErr := 0
		sec := Section{Header: secHeader}
		secName := sec.String()

		if (ImageSectionHeader{}) == secHeader {
			pe.Anomalies = append(pe.Anomalies, "Section `"+secName+"` Contents are null-bytes")
			countErr++
		}

		if secHeader.SizeOfRawData+secHeader.PointerToRawData > pe.size {
			pe.Anomalies = append(pe.Anomalies, "Section `"+secName+
				"` SizeOfRawData is larger than file")
			countErr++
		}

		if pe.adjustFileAlignment(secHeader.PointerToRawData) > pe.size {
			pe.Anomalies = append(pe.Anomalies, "Section `"+secName+
				"` PointerToRawData points beyond the end of the file")
			countErr++
		}

		if secHeader.VirtualSize > 0x10000000 {
			pe.Anomalies = append(pe.Anomalies, "Section `"+secName+
				"` VirtualSize is extremely large > 256MiB")
			countErr++
		}

		if pe.adjustSectionAlignment(secHeader.VirtualAddress) > 0x10000000 {
			pe.Anomalies = append(pe.Anomalies, "Section `"+secName+
				"` VirtualAddress is beyond 0x10000000")
			countErr++
		}

		var fileAlignment uint32
		switch pe.Is64 {
		case true:
			fileAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).FileAlignment
		case false:
			fileAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).FileAlignment
		}
		if fileAlignment != 0 && secHeader.PointerToRawData%fileAlignment != 0 {
			pe.Anomalies = append(pe.Anomalies, "Section `"+secName+
				"` PointerToRawData is not multiple of FileAlignment")
			countErr++
		}

		if countErr >= maxErr {
			break
		}

		// Append to the list of sections.
		if pe.opts.SectionEntropy {
			entropy := sec.CalculateEntropy(pe)
			sec.Entropy = &entropy
		}
		pe.Sections = append(pe.Sections, sec)

		offset += secHeaderSize
	}

	// Sort the sections by their VirtualAddress. This will allow to check
	// for potentially overlapping sections in badly constructed PEs.
	sort.Sort(byVirtualAddress(pe.Sections))

	if pe.NtHeader.FileHeader.NumberOfSections > 0 && len(pe.Sections) > 0 {
		offset += secHeaderSize * uint32(pe.NtHeader.FileHeader.NumberOfSections)
	}

	// There could be a problem if there are no raw data sections
	// greater than 0. Example: fc91013eb72529da005110a3403541b6
	// Should this throw an exception in the minimum header offset
	// can't be found?
	var rawDataPointers []uint32
	for _, sec := range pe.Sections {
		if sec.Header.PointerToRawData > 0 {
			rawDataPointers = append(
				rawDataPointers, pe.adjustFileAlignment(
					sec.Header.PointerToRawData))
		}
	}

	var lowestSectionOffset uint32
	if len(rawDataPointers) > 0 {
		lowestSectionOffset = Min(rawDataPointers)
	} else {
		lowestSectionOffset = 0
	}

	if lowestSectionOffset == 0 || lowestSectionOffset < offset {
		if offset <= pe.size {
			pe.Header = pe.data[:offset]
		}
	} else {
		if lowestSectionOffset <= pe.size {
			pe.Header = pe.data[:lowestSectionOffset]
		}
	}

	pe.HasSections = true
	return nil
}

// String stringifies the section name.
func (section *Section) String() string {
	return strings.Replace(string(section.Header.Name[:]), "\x00", "", -1)
}

// NextHeaderAddr returns the VirtualAddress of the next section.
func (section *Section) NextHeaderAddr(pe *File) uint32 {
	for i, currentSection := range pe.Sections {
		if i == len(pe.Sections)-1 {
			return 0
		}

		if section.Header == currentSection.Header {
			return pe.Sections[i+1].Header.VirtualAddress
		}
	}

	return 0
}

// Contains checks whether the section contains a given RVA.
func (section *Section) Contains(rva uint32, pe *File) bool {

	// Check if the SizeOfRawData is realistic. If it's bigger than the size of
	// the whole PE file minus the start address of the section it could be
	// either truncated or the SizeOfRawData contains a misleading value.
	// In either of those cases we take the VirtualSize.

	var size uint32
	adjustedPointer := pe.adjustFileAlignment(section.Header.PointerToRawData)
	if uint32(len(pe.data))-adjustedPointer < section.Header.SizeOfRawData {
		size = section.Header.VirtualSize
	} else {
		size = Max(section.Header.SizeOfRawData, section.Header.VirtualSize)
	}
	vaAdj := pe.adjustSectionAlignment(section.Header.VirtualAddress)

	// Check whether there's any section after the current one that starts before
	// the calculated end for the current one. If so, cut the current section's
	// size to fit in the range up to where the next section starts.
	if section.NextHeaderAddr(pe) != 0 &&
		section.NextHeaderAddr(pe) > section.Header.VirtualAddress &&
		vaAdj+size > section.NextHeaderAddr(pe) {
		size = section.NextHeaderAddr(pe) - vaAdj
	}

	return vaAdj <= rva && rva < vaAdj+size
}

// Data returns a data chunk from a section.
func (section *Section) Data(start, length uint32, pe *File) []byte {

	pointerToRawDataAdj := pe.adjustFileAlignment(
		section.Header.PointerToRawData)
	virtualAddressAdj := pe.adjustSectionAlignment(
		section.Header.VirtualAddress)

	var offset uint32
	if start == 0 {
		offset = pointerToRawDataAdj
	} else {
		offset = (start - virtualAddressAdj) + pointerToRawDataAdj
	}

	if offset > pe.size {
		return nil
	}

	var end uint32
	if length != 0 {
		end = offset + length
	} else {
		end = offset + section.Header.SizeOfRawData
	}

	// PointerToRawData is not adjusted here as we might want to read any possible
	// extra bytes that might get cut off by aligning the start (and hence cutting
	// something off the end)
	if end > section.Header.PointerToRawData+section.Header.SizeOfRawData &&
		section.Header.PointerToRawData+section.Header.SizeOfRawData > offset {
		end = section.Header.PointerToRawData + section.Header.SizeOfRawData
	}

	if end > pe.size {
		end = pe.size
	}

	return pe.data[offset:end]
}

// CalculateEntropy calculates section entropy.
func (section *Section) CalculateEntropy(pe *File) float64 {
	sectionData := section.Data(0, 0, pe)
	if sectionData == nil {
		return 0.0
	}

	sectionSize := float64(len(sectionData))
	if sectionSize == 0.0 {
		return 0.0
	}

	var frequencies [256]uint64
	for _, v := range sectionData {
		frequencies[v]++
	}

	var entropy float64
	for _, p := range frequencies {
		if p > 0 {
			freq := float64(p) / sectionSize
			entropy += freq * math.Log2(freq)
		}
	}

	return -entropy
}

// byVirtualAddress sorts all sections by Virtual Address.
type byVirtualAddress []Section

func (s byVirtualAddress) Len() int      { return len(s) }
func (s byVirtualAddress) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byVirtualAddress) Less(i, j int) bool {
	return s[i].Header.VirtualAddress < s[j].Header.VirtualAddress
}

// byPointerToRawData sorts all sections by PointerToRawData.
type byPointerToRawData []Section

func (s byPointerToRawData) Len() int      { return len(s) }
func (s byPointerToRawData) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byPointerToRawData) Less(i, j int) bool {
	return s[i].Header.PointerToRawData < s[j].Header.PointerToRawData
}

// PrettySectionFlags returns the string representations of the `Flags` field
// of section header.
func (section *Section) PrettySectionFlags() []string {
	var values []string

	sectionFlags := map[uint32]string{
		//ImageSectionReserved1:            "Reserved1",
		ImageSectionReserved2:            "Reserved2",
		ImageSectionReserved3:            "Reserved3",
		ImageSectionReserved4:            "Reserved4",
		ImageSectionTypeNoPad:            "No Padd",
		ImageSectionReserved5:            "Reserved5",
		ImageSectionCntCode:              "Contains Code",
		ImageSectionCntInitializedData:   "Initialized Data",
		ImageSectionCntUninitializedData: "Uninitialized Data",
		ImageSectionLnkOther:             "Lnk Other",
		ImageSectionLnkInfo:              "Lnk Info",
		ImageSectionReserved6:            "Reserved6",
		ImageSectionLnkRemove:            "LnkRemove",
		ImageSectionLnkCOMDAT:            "LnkCOMDAT",
		ImageSectionGpRel:                "GpReferenced",
		ImageSectionMemPurgeable:         "Purgeable",
		ImageSectionMemLocked:            "Locked",
		ImageSectionMemPreload:           "Preload",
		ImageSectionAlign1Bytes:          "Align1Bytes",
		ImageSectionAlign2Bytes:          "Align2Bytes",
		ImageSectionAlign4Bytes:          "Align4Bytes",
		ImageSectionAlign8Bytes:          "Align8Bytes",
		ImageSectionAlign16Bytes:         "Align16Bytes",
		ImageSectionAlign32Bytes:         "Align32Bytes",
		ImageSectionAlign64Bytes:         "Align64Bytes",
		ImageSectionAlign128Bytes:        "Align128Bytes",
		ImageSectionAlign256Bytes:        "Align256Bytes",
		ImageSectionAlign512Bytes:        "Align512Bytes",
		ImageSectionAlign1024Bytes:       "Align1024Bytes",
		ImageSectionAlign2048Bytes:       "Align2048Bytes",
		ImageSectionAlign4096Bytes:       "Align4096Bytes",
		ImageSectionAlign8192Bytes:       "Align8192Bytes",
		ImageSectionLnkMRelocOvfl:        "ExtendedReloc",
		ImageSectionMemDiscardable:       "Discardable",
		ImageSectionMemNotCached:         "NotCached",
		ImageSectionMemNotPaged:          "NotPaged",
		ImageSectionMemShared:            "Shared",
		ImageSectionMemExecute:           "Executable",
		ImageSectionMemRead:              "Readable",
		ImageSectionMemWrite:             "Writable",
	}

	flags := section.Header.Characteristics
	for k, v := range sectionFlags {
		if (k & flags) == k {
			values = append(values, v)
		}
	}

	return values
}

// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"math"
	"reflect"
	"sort"
	"strings"
)

const (
	// ImageScnReserved1 for future use.
	ImageScnReserved1 = 0x00000000

	// ImageScnReserved2 for future use.
	ImageScnReserved2 = 0x00000001

	// ImageScnReserved3 for future use.
	ImageScnReserved3 = 0x00000002

	// ImageScnReserved4 for future use.
	ImageScnReserved4 = 0x00000004

	// ImageScnTypeNoPad indicates the section should not be padded to the next
	// boundary. This flag is obsolete and is replaced by ImageScnAlign1Bytes.
	// This is valid only for object files.
	ImageScnTypeNoPad = 0x00000008

	// ImageScnReserved5 for future use.
	ImageScnReserved5 = 0x00000010

	// ImageScnCntCode indicates the section contains executable code.
	ImageScnCntCode = 0x00000020

	// ImageScnCntInitializedData indicates the section contains initialized
	// data.
	ImageScnCntInitializedData = 0x00000040

	// ImageScnCntUninitializedData indicates the section contains uninitialized
	// data.
	ImageScnCntUninitializedData = 0x00000080

	// ImageScnLnkOther is reserved for future use.
	ImageScnLnkOther = 0x00000100

	// ImageScnLnkInfo indicates the section contains comments or other
	// information. The .drectve section has this type. This is valid for
	// object files only.
	ImageScnLnkInfo = 0x00000200

	// ImageScnReserved6 for future use.
	ImageScnReserved6 = 0x00000400

	// ImageScnLnkRemove indicates the section will not become part of the image
	// This is valid only for object files.
	ImageScnLnkRemove = 0x00000800

	// ImageScnLnkComdat indicates the section contains COMDAT data. For more
	// information, see COMDAT Sections (Object Only). This is valid only for
	// object files.
	ImageScnLnkComdat = 0x00001000

	// ImageScnGpRel indicates the section contains data referenced through the
	// global pointer (GP).
	ImageScnGpRel = 0x00008000

	// ImageScnMemPurgeable is reserved for future use.
	ImageScnMemPurgeable = 0x00020000

	// ImageScnMem16Bit is reserved for future use.
	ImageScnMem16Bit = 0x00020000

	// ImageScnMemLocked is reserved for future use.
	ImageScnMemLocked = 0x00040000

	// ImageScnMemPreload is reserved for future use.
	ImageScnMemPreload = 0x00080000

	// ImageScnAlign1Bytes indicates to align data on a 1-byte boundary.
	// Valid only for object files.
	ImageScnAlign1Bytes = 0x00100000

	// ImageScnAlign2Bytes indicates to align data on a 2-byte boundary.
	// Valid only for object files.
	ImageScnAlign2Bytes = 0x00200000

	// ImageScnAlign4Bytes indicates to align data on a 4-byte boundary.
	// Valid only for object files.
	ImageScnAlign4Bytes = 0x00300000

	// ImageScnAlign8Bytes indicates to align data on a 8-byte boundary.
	// Valid only for object files.
	ImageScnAlign8Bytes = 0x00400000

	// ImageScnAlign16Bytes indicates to align data on a 16-byte boundary.
	// Valid only for object files.
	ImageScnAlign16Bytes = 0x00500000

	// ImageScnAlign32Bytes indicates to align data on a 32-byte boundary.
	// Valid only for object files.
	ImageScnAlign32Bytes = 0x00600000

	// ImageScnAlign64Bytes indicates to align data on a 64-byte boundary.
	// Valid only for object files.
	ImageScnAlign64Bytes = 0x00700000

	// ImageScnAlign128Bytes indicates to align data on a 128-byte boundary.
	// Valid only for object files.
	ImageScnAlign128Bytes = 0x00800000

	// ImageScnAlign256Bytes indicates to align data on a 256-byte boundary.
	// Valid only for object files.
	ImageScnAlign256Bytes = 0x00900000

	// ImageScnAlign512Bytes indicates to align data on a 512-byte boundary.
	// Valid only for object files.
	ImageScnAlign512Bytes = 0x00A00000

	// ImageScnAlign1024Bytes indicates to align data on a 1024-byte boundary.
	// Valid only for object files.
	ImageScnAlign1024Bytes = 0x00B00000

	// ImageScnAlign2048Bytes indicates to align data on a 2048-byte boundary.
	// Valid only for object files.
	ImageScnAlign2048Bytes = 0x00C00000

	// ImageScnAlign4096Bytes indicates to align data on a 4096-byte boundary.
	// Valid only for object files.
	ImageScnAlign4096Bytes = 0x00D00000

	// ImageScnAlign8192Bytes indicates to align data on a 8192-byte boundary.
	// Valid only for object files.
	ImageScnAlign8192Bytes = 0x00E00000

	// ImageScnLnkMRelocOvfl indicates the section contains extended
	// relocations.
	ImageScnLnkMRelocOvfl = 0x01000000

	// ImageScnMemDiscardable indicates the section can be discarded as needed.
	ImageScnMemDiscardable = 0x02000000

	// ImageScnMemNotCached indicates the  section cannot be cached.
	ImageScnMemNotCached = 0x04000000

	// ImageScnMemNotPaged indicates the section is not pageable.
	ImageScnMemNotPaged = 0x08000000

	// ImageScnMemShared indicates the section can be shared in memory.
	ImageScnMemShared = 0x10000000

	// ImageScnMemExecute indicates the section can be executed as code.
	ImageScnMemExecute = 0x20000000

	// ImageScnMemRead indicates the section can be read.
	ImageScnMemRead = 0x40000000

	// ImageScnMemWrite indicates the section can be written to.
	ImageScnMemWrite = 0x80000000
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
	Name [8]uint8

	// The total size of the section when loaded into memory. If this value is
	// greater than SizeOfRawData, the section is zero-padded. This field is
	// valid only for executable images and should be set to zero for object files.
	VirtualSize uint32

	// For executable images, the address of the first byte of the section
	// relative to the image base when the section is loaded into memory.
	// For object files, this field is the address of the first byte before
	// relocation is applied; for simplicity, compilers should set this to zero.
	// Otherwise, it is an arbitrary value that is subtracted from offsets during
	// relocation.
	VirtualAddress uint32

	// The size of the section (for object files) or the size of the initialized
	// data on disk (for image files). For executable images, this must be a
	// multiple of FileAlignment from the optional header. If this is less than
	// VirtualSize, the remainder of the section is zero-filled. Because the
	// SizeOfRawData field is rounded but the VirtualSize field is not, it is
	// possible for SizeOfRawData to be greater than VirtualSize as well. When
	// a section contains only uninitialized data, this field should be zero.
	SizeOfRawData uint32

	// The file pointer to the first page of the section within the COFF file.
	// For executable images, this must be a multiple of FileAlignment from the
	// optional header. For object files, the value should be aligned on a
	// 4-byte boundary for best performance. When a section contains only
	// uninitialized data, this field should be zero.
	PointerToRawData uint32

	// The file pointer to the beginning of relocation entries for the section.
	// This is set to zero for executable images or if there are no relocations.
	PointerToRelocations uint32

	// The file pointer to the beginning of line-number entries for the section.
	// This is set to zero if there are no COFF line numbers. This value should
	// be zero for an image because COFF debugging information is deprecated.
	PointerToLineNumbers uint32

	// The number of relocation entries for the section.
	// This is set to zero for executable images.
	NumberOfRelocations uint16

	// The number of line-number entries for the section. This value should be
	// zero for an image because COFF debugging information is deprecated.
	NumberOfLineNumbers uint16

	// The flags that describe the characteristics of the section.
	Characteristics uint32
}

// Section represents a PE section header, plus additional data like entropy.
type Section struct {
	Header  ImageSectionHeader
	Entropy float64 `json:",omitempty"`
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
			sec.Entropy = sec.CalculateEntropy(pe)
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

		if reflect.DeepEqual(section.Header, &currentSection.Header) {
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

// PrettySectionFlags returns the string representations of the `Flags` field of section header.
func (section *Section) PrettySectionFlags() []string {
	var values []string

	sectionFlags := map[uint32]string{
		//ImageScnReserved1:            "Reserved1",
		ImageScnReserved2:            "Reserved2",
		ImageScnReserved3:            "Reserved3",
		ImageScnReserved4:            "Reserved4",
		ImageScnTypeNoPad:            "No Padd",
		ImageScnReserved5:            "Reserved5",
		ImageScnCntCode:              "Contains Code",
		ImageScnCntInitializedData:   "Initialized Data",
		ImageScnCntUninitializedData: "Uninitialized Data",
		ImageScnLnkOther:             "Lnk Other",
		ImageScnLnkInfo:              "Lnk Info",
		ImageScnReserved6:            "Reserved6",
		ImageScnLnkRemove:            "LnkRemove",
		ImageScnLnkComdat:            "LnkComdat",
		ImageScnGpRel:                "GpReferenced",
		ImageScnMemPurgeable:         "Purgeable",
		ImageScnMemLocked:            "Locked",
		ImageScnMemPreload:           "Preload",
		ImageScnAlign1Bytes:          "Align1Bytes",
		ImageScnAlign2Bytes:          "Align2Bytes",
		ImageScnAlign4Bytes:          "Align4Bytes",
		ImageScnAlign8Bytes:          "Align8Bytes",
		ImageScnAlign16Bytes:         "Align16Bytes",
		ImageScnAlign32Bytes:         "Align32Bytes",
		ImageScnAlign64Bytes:         "Align64Bytes",
		ImageScnAlign128Bytes:        "Align128Bytes",
		ImageScnAlign256Bytes:        "Align256Bytes",
		ImageScnAlign512Bytes:        "Align512Bytes",
		ImageScnAlign1024Bytes:       "Align1024Bytes",
		ImageScnAlign2048Bytes:       "Align2048Bytes",
		ImageScnAlign4096Bytes:       "Align4096Bytes",
		ImageScnAlign8192Bytes:       "Align8192Bytes",
		ImageScnLnkMRelocOvfl:        "ExtendedReloc",
		ImageScnMemDiscardable:       "Discardable",
		ImageScnMemNotCached:         "NotCached",
		ImageScnMemNotPaged:          "NotPaged",
		ImageScnMemShared:            "Shared",
		ImageScnMemExecute:           "Executable",
		ImageScnMemRead:              "Readable",
		ImageScnMemWrite:             "Writable",
	}

	flags := section.Header.Characteristics
	for k, v := range sectionFlags {
		if (k & flags) == k {
			values = append(values, v)
		}
	}

	return values
}

// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/text/encoding/unicode"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// TinyPESize On Windows XP (x32) the smallest PE executable is 97 bytes.
	TinyPESize = 97

	// FileAlignmentHardcodedValue represents the value which PointerToRawData
	// should be at least equal or bigger to, or it will be rounded to zero.
	// According to http://corkami.blogspot.com/2010/01/parce-que-la-planche-aura-brule.html
	// if PointerToRawData is less that 0x200 it's rounded to zero.
	FileAlignmentHardcodedValue = 0x200
)

// Errors
var (

	// ErrInvalidPESize is returned when the file size is less that the smallest
	// PE file size possible.ErrImageOS2SignatureFound
	ErrInvalidPESize = errors.New("not a PE file, smaller than tiny PE")

	// ErrDOSMagicNotFound is returned when file is potentially a ZM executable.
	ErrDOSMagicNotFound = errors.New("DOS Header magic not found")

	// ErrInvalidElfanewValue is returned when e_lfanew is larger than file size.
	ErrInvalidElfanewValue = errors.New("invalid e_lfanew value. Probably not a PE file")

	// ErrInvalidNtHeaderOffset is returned when the NT Header offset is beyond
	// the image file.
	ErrInvalidNtHeaderOffset = errors.New(
		"invalid NT Header Offset. NT Header Signature not found")

	// ErrImageOS2SignatureFound is returned when signature is for a NE file.
	ErrImageOS2SignatureFound = errors.New(
		"not a valid PE signature. Probably a NE file")

	// ErrImageOS2LESignatureFound is returned when signature is for a LE file.
	ErrImageOS2LESignatureFound = errors.New(
		"not a valid PE signature. Probably an LE file")

	// ErrImageVXDSignatureFound is returned when signature is for a LX file.
	ErrImageVXDSignatureFound = errors.New(
		"not a valid PE signature. Probably an LX file")

	// ErrImageTESignatureFound is returned when signature is for a TE file.
	ErrImageTESignatureFound = errors.New(
		"not a valid PE signature. Probably a TE file")

	// ErrImageNtSignatureNotFound is returned when PE magic signature is not found.
	ErrImageNtSignatureNotFound = errors.New(
		"not a valid PE signature. Magic not found")

	// ErrImageNtOptionalHeaderMagicNotFound is returned when optional header
	// magic is different from PE32/PE32+.
	ErrImageNtOptionalHeaderMagicNotFound = errors.New(
		"not a valid PE signature. Optional Header magic not found")

	// ErrImageBaseNotAligned is reported when the image base is not aligned to 64K.
	ErrImageBaseNotAligned = errors.New(
		"corrupt PE file. Image base not aligned to 64 K")

	// AnoImageBaseOverflow is reported when the image base + SizeOfImage is
	// larger than 80000000h/FFFF080000000000h in PE32/P32+.
	AnoImageBaseOverflow = "Image base beyond allowed address"

	// ErrInvalidSectionFileAlignment is reported when section alignment is less than a
	// PAGE_SIZE and section alignment != file alignment.
	ErrInvalidSectionFileAlignment = errors.New("corrupt PE file. Section " +
		"alignment is less than a PAGE_SIZE and section alignment != file alignment")

	// AnoInvalidSizeOfImage is reported when SizeOfImage is not multiple of
	// SectionAlignment.
	AnoInvalidSizeOfImage = "Invalid SizeOfImage value, should be multiple " +
		"of SectionAlignment"

	// ErrOutsideBoundary is reported when attempting to read an address beyond
	// file image limits.
	ErrOutsideBoundary = errors.New("reading data outside boundary")
)

// Max returns the larger of x or y.
func Max(x, y uint32) uint32 {
	if x < y {
		return y
	}
	return x
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// Min returns the min number in a slice.
func Min(values []uint32) uint32 {
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

// IsValidDosFilename returns true if the DLL name is likely to be valid.
// Valid FAT32 8.3 short filename characters according to:
// http://en.wikipedia.org/wiki/8.3_filename
// The filename length is not checked because the DLLs filename
// can be longer that the 8.3
func IsValidDosFilename(filename string) bool {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals := "0123456789"
	special := "!#$%&'()-@^_`{}~+,.;=[]\\/"
	charset := alphabet + numerals + special
	for _, c := range filename {
		if !strings.Contains(charset, string(c)) {
			return false
		}
	}
	return true
}

// IsValidFunctionName checks if an imported name uses the valid accepted
// characters expected in mangled function names. If the symbol's characters
// don't fall within this charset we will assume the name is invalid.
func IsValidFunctionName(functionName string) bool {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals := "0123456789"
	special := "_?@$()<>"
	charset := alphabet + numerals + special
	for _, c := range charset {
		if !strings.Contains(charset, string(c)) {
			return false
		}
	}
	return true
}

// IsPrintable checks weather a string is printable.
func IsPrintable(s string) bool {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals := "0123456789"
	whitespace := " \t\n\r\v\f"
	special := "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	charset := alphabet + numerals + special + whitespace
	for _, c := range charset {
		if !strings.Contains(charset, string(c)) {
			return false
		}
	}
	return true
}

// getSectionByRva returns the section containing the given address.
func (pe *File) getSectionByRva(rva uint32) *Section {
	for _, section := range pe.Sections {
		if section.Contains(rva, pe) {
			return &section
		}
	}
	return nil
}

// getSectionByRva returns the section name containing the given address.
func (pe *File) getSectionNameByRva(rva uint32) string {
	for _, section := range pe.Sections {
		if section.Contains(rva, pe) {
			return section.String()
		}
	}
	return ""
}

func (pe *File) getSectionByOffset(offset uint32) *Section {
	for _, section := range pe.Sections {
		if section.Header.PointerToRawData == 0 {
			continue
		}

		adjustedPointer := pe.adjustFileAlignment(
			section.Header.PointerToRawData)
		if adjustedPointer <= offset &&
			offset < (adjustedPointer+section.Header.SizeOfRawData) {
			return &section
		}
	}
	return nil
}

// GetOffsetFromRva returns the file offset corresponding to this RVA.
func (pe *File) GetOffsetFromRva(rva uint32) uint32 {

	// Given a RVA, this method will find the section where the
	// data lies and return the offset within the file.
	section := pe.getSectionByRva(rva)
	if section == nil {
		if rva < uint32(len(pe.data)) {
			return rva
		}
		return ^uint32(0)
	}
	sectionAlignment := pe.adjustSectionAlignment(section.Header.VirtualAddress)
	fileAlignment := pe.adjustFileAlignment(section.Header.PointerToRawData)
	return rva - sectionAlignment + fileAlignment
}

// GetRVAFromOffset returns an RVA given an offset.
func (pe *File) GetRVAFromOffset(offset uint32) uint32 {
	section := pe.getSectionByOffset(offset)
	minAddr := ^uint32(0)
	if section == nil {

		if len(pe.Sections) == 0 {
			return offset
		}

		for _, section := range pe.Sections {
			vaddr := pe.adjustSectionAlignment(section.Header.VirtualAddress)
			if vaddr < minAddr {
				minAddr = vaddr
			}
		}
		// Assume that offset lies within the headers
		// The case illustrating this behavior can be found at:
		// http://corkami.blogspot.com/2010/01/hey-hey-hey-whats-in-your-head.html
		// where the import table is not contained by any section
		// hence the RVA needs to be resolved to a raw offset
		if offset < minAddr {
			return offset
		}

		pe.logger.Warn("data at Offset can't be fetched. Corrupt header?")
		return ^uint32(0)
	}
	sectionAlignment := pe.adjustSectionAlignment(section.Header.VirtualAddress)
	fileAlignment := pe.adjustFileAlignment(section.Header.PointerToRawData)
	return offset - fileAlignment + sectionAlignment
}

func (pe *File) getSectionByName(secName string) (section *ImageSectionHeader) {
	for _, section := range pe.Sections {
		if section.String() == secName {
			return &section.Header
		}

	}
	return nil
}

// getStringAtRVA returns an ASCII string located at the given address.
func (pe *File) getStringAtRVA(rva, maxLen uint32) string {
	if rva == 0 {
		return ""
	}

	section := pe.getSectionByRva(rva)
	if section == nil {
		if rva > pe.size {
			return ""
		}

		end := rva + maxLen
		if end > pe.size {
			end = pe.size
		}
		s := pe.GetStringFromData(0, pe.data[rva:end])
		return string(s)
	}
	s := pe.GetStringFromData(0, section.Data(rva, maxLen, pe))
	return string(s)
}

func (pe *File) readUnicodeStringAtRVA(rva uint32, maxLength uint32) string {
	str := ""
	offset := pe.GetOffsetFromRva(rva)
	i := uint32(0)
	for i = 0; i < maxLength; i += 2 {
		if offset+i >= pe.size || pe.data[offset+i] == 0 {
			break
		}

		str += string(pe.data[offset+i])
	}
	return str
}

func (pe *File) readASCIIStringAtOffset(offset, maxLength uint32) (uint32, string) {
	str := ""
	i := uint32(0)

	for i = 0; i < maxLength; i++ {
		if offset+i >= pe.size || pe.data[offset+i] == 0 {
			break
		}

		str += string(pe.data[offset+i])
	}
	return i, str
}

// GetStringFromData returns ASCII string from within the data.
func (pe *File) GetStringFromData(offset uint32, data []byte) []byte {

	dataSize := uint32(len(data))
	if dataSize == 0 {
		return nil
	}

	if offset > dataSize {
		return nil
	}

	end := offset
	for end < dataSize {
		if data[end] == 0 {
			break
		}
		end++
	}
	return data[offset:end]
}

// getStringAtOffset returns a string given an offset.
func (pe *File) getStringAtOffset(offset, size uint32) (string, error) {
	if offset+size > pe.size {
		return "", ErrOutsideBoundary
	}

	str := string(pe.data[offset : offset+size])
	return strings.Replace(str, "\x00", "", -1), nil
}

// GetData returns the data given an RVA regardless of the section where it
// lies on.
func (pe *File) GetData(rva, length uint32) ([]byte, error) {

	// Given a RVA and the size of the chunk to retrieve, this method
	// will find the section where the data lies and return the data.
	section := pe.getSectionByRva(rva)

	var end uint32
	if length > 0 {
		end = rva + length
	} else {
		end = 0
	}

	if section == nil {
		if rva < uint32(len(pe.Header)) {
			return pe.Header[rva:end], nil
		}

		// Before we give up we check whether the file might contain the data
		// anyway. There are cases of PE files without sections that rely on
		// windows loading the first 8291 bytes into memory and assume the data
		// will be there. A functional file with these characteristics is:
		// MD5: 0008892cdfbc3bda5ce047c565e52295
		// SHA-1: c7116b9ff950f86af256defb95b5d4859d4752a9

		if rva < uint32(len(pe.data)) {
			return pe.data[rva:end], nil
		}

		return nil, errors.New("data at RVA can't be fetched. Corrupt header?")
	}
	return section.Data(rva, length, pe), nil
}

// The alignment factor (in bytes) that is used to align the raw data of sections
// in the image file. The value should be a power of 2 between 512 and 64 K,
// inclusive. The default is 512. If the SectionAlignment is less than the
// architecture's page size, then FileAlignment must match SectionAlignment.
func (pe *File) adjustFileAlignment(va uint32) uint32 {

	var fileAlignment uint32
	switch pe.Is64 {
	case true:
		fileAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).FileAlignment
	case false:
		fileAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).FileAlignment
	}

	if fileAlignment > FileAlignmentHardcodedValue && fileAlignment%2 != 0 {
		pe.Anomalies = append(pe.Anomalies, ErrInvalidFileAlignment)
	}

	if fileAlignment < FileAlignmentHardcodedValue {
		return va
	}

	// round it to 0x200 if not power of 2.
	// According to https://github.com/corkami/docs/blob/master/PE/PE.md
	// if PointerToRawData is less that 0x200 it's rounded to zero. Loading the
	// test file in a debugger it's easy to verify that the PointerToRawData
	// value of 1 is rounded to zero. Hence we reproduce the behavior
	return (va / 0x200) * 0x200

}

// The alignment (in bytes) of sections when they are loaded into memory
// It must be greater than or equal to FileAlignment. The default is the
// page size for the architecture.
func (pe *File) adjustSectionAlignment(va uint32) uint32 {
	var fileAlignment, sectionAlignment uint32

	switch pe.Is64 {
	case true:
		fileAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).FileAlignment
		sectionAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).SectionAlignment
	case false:
		fileAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).FileAlignment
		sectionAlignment = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).SectionAlignment
	}

	if fileAlignment < FileAlignmentHardcodedValue &&
		fileAlignment != sectionAlignment {
		pe.Anomalies = append(pe.Anomalies, ErrInvalidSectionAlignment)
	}

	if sectionAlignment < 0x1000 { // page size
		sectionAlignment = fileAlignment
	}

	// 0x200 is the minimum valid FileAlignment according to the documentation
	// although ntoskrnl.exe has an alignment of 0x80 in some Windows versions
	if sectionAlignment != 0 && va%sectionAlignment != 0 {
		return sectionAlignment * (va / sectionAlignment)
	}
	return va
}

// alignDword aligns the offset on a 32-bit boundary.
func alignDword(offset, base uint32) uint32 {
	return ((offset + base + 3) & 0xfffffffc) - (base & 0xfffffffc)
}

// stringInSlice checks weather a string exists in a slice of strings.
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// intInSlice checks weather a uint32 exists in a slice of uint32.
func intInSlice(a uint32, list []uint32) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// IsDriver returns true if the PE file is a Windows driver.
func (pe *File) IsDriver() bool {

	// Checking that the ImageBase field of the OptionalHeader is above or
	// equal to 0x80000000 (that is, whether it lies in the upper 2GB of
	//the address space, normally belonging to the kernel) is not a
	// reliable enough indicator.  For instance, PEs that play the invalid
	// ImageBase trick to get relocated could be incorrectly assumed to be
	// drivers.

	// Checking if any section characteristics have the IMAGE_SCN_MEM_NOT_PAGED
	// flag set is not reliable either.

	// If there's still no import directory (the PE doesn't have one or it's
	// malformed), give up.
	if len(pe.Imports) == 0 {
		return false
	}

	// DIRECTORY_ENTRY_IMPORT will now exist, although it may be empty.
	// If it imports from "ntoskrnl.exe" or other kernel components it should
	// be a driver.
	systemDLLs := []string{"ntoskrnl.exe", "hal.dll", "ndis.sys",
		"bootvid.dll", "kdcom.dll"}
	for _, dll := range pe.Imports {
		if stringInSlice(strings.ToLower(dll.Name), systemDLLs) {
			return true
		}
	}

	// If still we couldn't tell, check common driver section with combination
	// of IMAGE_SUBSYSTEM_NATIVE or IMAGE_SUBSYSTEM_NATIVE_WINDOWS.
	subsystem := ImageOptionalHeaderSubsystemType(0)
	oh32 := ImageOptionalHeader32{}
	oh64 := ImageOptionalHeader64{}
	switch pe.Is64 {
	case true:
		oh64 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64)
		subsystem = oh64.Subsystem
	case false:
		oh32 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32)
		subsystem = oh32.Subsystem
	}
	commonDriverSectionNames := []string{"page", "paged", "nonpage", "init"}
	for _, section := range pe.Sections {
		s := strings.ToLower(section.String())
		if stringInSlice(s, commonDriverSectionNames) &&
			(subsystem&ImageSubsystemNativeWindows != 0 ||
				subsystem&ImageSubsystemNative != 0) {
			return true
		}

	}

	return false
}

// IsDLL returns true if the PE file is a standard DLL.
func (pe *File) IsDLL() bool {
	return pe.NtHeader.FileHeader.Characteristics&ImageFileDLL != 0
}

// IsEXE returns true if the PE file is a standard executable.
func (pe *File) IsEXE() bool {

	// Returns true only if the file has the IMAGE_FILE_EXECUTABLE_IMAGE flag set
	// and the IMAGE_FILE_DLL not set and the file does not appear to be a driver either.
	if pe.IsDLL() || pe.IsDriver() {
		return false
	}

	if pe.NtHeader.FileHeader.Characteristics&ImageFileExecutableImage == 0 {
		return false
	}

	return true
}

// Checksum calculates the PE checksum as generated by CheckSumMappedFile().
func (pe *File) Checksum() uint32 {
	var checksum uint64 = 0
	var max uint64 = 0x100000000
	currentDword := uint32(0)

	// Get the Checksum offset.
	optionalHeaderOffset := pe.DOSHeader.AddressOfNewEXEHeader + 4 +
		uint32(binary.Size(pe.NtHeader.FileHeader))

	// `CheckSum` field position in optional PE headers is always 64 for PE and PE+.
	checksumOffset := optionalHeaderOffset + 64

	// Verify the data is DWORD-aligned and add padding if needed
	remainder := pe.size % 4
	dataLen := pe.size
	if remainder > 0 {
		dataLen = pe.size + (4 - remainder)
		paddedBytes := make([]byte, 4-remainder)
		pe.data = append(pe.data, paddedBytes...)
	}

	for i := uint32(0); i < dataLen; i += 4 {
		// Skip the checksum field.
		if i == checksumOffset {
			continue
		}

		// Read DWORD from file.
		currentDword = binary.LittleEndian.Uint32(pe.data[i:])

		// Calculate checksum.
		checksum = (checksum & 0xffffffff) + uint64(currentDword) + (checksum >> 32)
		if checksum > max {
			checksum = (checksum & 0xffffffff) + (checksum >> 32)
		}
	}

	checksum = (checksum & 0xffff) + (checksum >> 16)
	checksum = checksum + (checksum >> 16)
	checksum = checksum & 0xffff

	// The length is the one of the original data, not the padded one
	checksum += uint64(pe.size)

	return uint32(checksum)
}

// ReadUint64 read a uint64 from a buffer.
func (pe *File) ReadUint64(offset uint32) (uint64, error) {
	if offset+8 > pe.size {
		return 0, ErrOutsideBoundary
	}

	return binary.LittleEndian.Uint64(pe.data[offset:]), nil
}

// ReadUint32 read a uint32 from a buffer.
func (pe *File) ReadUint32(offset uint32) (uint32, error) {
	if offset > pe.size-4 {
		return 0, ErrOutsideBoundary
	}

	return binary.LittleEndian.Uint32(pe.data[offset:]), nil
}

// ReadUint16 read a uint16 from a buffer.
func (pe *File) ReadUint16(offset uint32) (uint16, error) {
	if offset > pe.size-2 {
		return 0, ErrOutsideBoundary
	}

	return binary.LittleEndian.Uint16(pe.data[offset:]), nil
}

// ReadUint8 read a uint8 from a buffer.
func (pe *File) ReadUint8(offset uint32) (uint8, error) {
	if offset+1 > pe.size {
		return 0, ErrOutsideBoundary
	}

	b := pe.data[offset : offset+1][0]
	return uint8(b), nil
}

func (pe *File) structUnpack(iface interface{}, offset, size uint32) (err error) {
	// Boundary check
	totalSize := offset + size

	// Integer overflow
	if (totalSize > offset) != (size > 0) {
		return ErrOutsideBoundary
	}

	if offset >= pe.size || totalSize > pe.size {
		return ErrOutsideBoundary
	}

	buf := bytes.NewReader(pe.data[offset : offset+size])
	err = binary.Read(buf, binary.LittleEndian, iface)
	if err != nil {
		return err
	}
	return nil
}

// ReadBytesAtOffset returns a byte array from offset.
func (pe *File) ReadBytesAtOffset(offset, size uint32) ([]byte, error) {
	// Boundary check
	totalSize := offset + size

	// Integer overflow
	if (totalSize > offset) != (size > 0) {
		return nil, ErrOutsideBoundary
	}

	if offset >= pe.size || totalSize > pe.size {
		return nil, ErrOutsideBoundary
	}

	return pe.data[offset : offset+size], nil
}

// DecodeUTF16String decodes the UTF16 string from the byte slice.
func DecodeUTF16String(b []byte) (string, error) {
	n := bytes.Index(b, []byte{0, 0})
	if n == 0 {
		return "", nil
	}
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
	s, err := decoder.Bytes(b[0 : n+1])
	if err != nil {
		return "", err
	}
	return string(s), nil
}

// IsBitSet returns true when a bit on a particular position is set.
func IsBitSet(n uint64, pos int) bool {
	val := n & (1 << pos)
	return (val > 0)
}

func getAbsoluteFilePath(testfile string) string {
	_, p, _, _ := runtime.Caller(0)
	return path.Join(filepath.Dir(p), testfile)
}

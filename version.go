// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	// VersionResourceType identifies the version resource type in the resource directory
	VersionResourceType = 16

	// VsVersionInfoString is the UTF16-encoded string that identifies the VS_VERSION_INFO block
	VsVersionInfoString = "VS_VERSION_INFO"

	// VsFileInfoSignature is the file info signature
	VsFileInfoSignature uint32 = 0xFEEF04BD

	// StringFileInfoString is the UTF16-encoded string that identifies the StringFileInfo block
	StringFileInfoString = "StringFileInfo"
	// VarFileInfoString is the UTF16-encoded string that identifies the VarFileInfoString block
	VarFileInfoString = "VarFileInfo"

	// VsVersionInfoStringLength specifies the length of the VS_VERSION_INFO structure
	VsVersionInfoStringLength uint32 = 6
	// StringFileInfoLength specifies length of the StringFileInfo structure
	StringFileInfoLength uint32 = 6
	// StringTableLength specifies the length of the StringTable structure
	StringTableLength uint32 = 6
	// StringLength specifies the length of the String structure
	StringLength uint32 = 6
	// LangIDLength specifies the length of the language identifier string.
	// It is represented as 8-digit hexadecimal number stored as a Unicode string.
	LangIDLength uint32 = 8*2 + 1
)

// VsVersionInfo represents the organization of data in
// a file-version resource. It is the root structure that
// contains all other file-version information structures.
type VsVersionInfo struct {
	// Length is the length, in bytes, of the VS_VERSIONINFO structure.
	// This length does not include any padding that aligns any
	// subsequent version resource data on a 32-bit boundary.
	Length uint16 `json:"length"`
	// ValueLength is the length, in bytes, of arbitrary data associated
	// with the VS_VERSIONINFO structure.
	// This value is zero if there is no any data associated with the
	// current version structure.
	ValueLength uint16 `json:"value_length"`
	// Type represents as many zero words as necessary to align the StringFileInfo
	// and VarFileInfo structures on a 32-bit boundary. These bytes are not included
	// in ValueLength.
	Type uint16 `json:"type"`
}

func (pe *File) parseVersionInfo(e ResourceDirectoryEntry) (*VsVersionInfo, error) {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData)
	b, err := pe.ReadBytesAtOffset(offset, e.Data.Struct.Size)
	if err != nil {
		return nil, err
	}
	var v VsVersionInfo
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &v); err != nil {
		return nil, err
	}
	b, err = pe.ReadBytesAtOffset(offset+VsVersionInfoStringLength, uint32(v.ValueLength))
	if err != nil {
		return nil, err
	}
	vsVersionString, err := DecodeUTF16String(b)
	if err != nil {
		return nil, err
	}
	if vsVersionString != VsVersionInfoString {
		return nil, fmt.Errorf("invalid VS_VERSION_INFO block. %s", vsVersionString)
	}
	return &v, nil
}

// VsFixedFileInfo contains version information for a file.
// This information is language and code page independent.
type VsFixedFileInfo struct {
	// Signature contains the value 0xFEEF04BD. This is used
	// with the `key` member of the VS_VERSIONINFO structure
	// when searching a file for the VS_FIXEDFILEINFO structure.
	Signature uint32 `json:"signature"`
	// StructVer is the binary version number of this structure.
	// The high-order word of this member contains the major version
	// number, and the low-order word contains the minor version number.
	StructVer uint32 `json:"struct_ver"`
	// FileVersionMS denotes the most significant 32 bits of the file's
	// binary version number.
	FileVersionMS uint32 `json:"file_version_ms"`
	// FileVersionLS denotes the least significant 32 bits of the file's
	// binary version number.
	FileVersionLS uint32 `json:"file_version_ls"`
	// ProductVersionMS represents the most significant 32 bits of the
	// binary version number of the product with which this file was distributed.
	ProductVersionMS uint32 `json:"product_version_ms"`
	// ProductVersionLS represents the most significant 32 bits of the
	// binary version number of the product with which this file was distributed.
	ProductVersionLS uint32 `json:"product_version_ls"`
	// FileFlagMask contains a bitmask that specifies the valid bits in FileFlags.
	// A bit is valid only if it was defined when the file was created.
	FileFlagMask uint32 `json:"file_flag_mask"`
	// FileFlags contains a bitmask that specifies the Boolean attributes of the file.
	// For example, the file contains debugging information or is compiled with debugging
	// features enabled if FileFlags is equal to 0x00000001L (VS_FF_DEBUG).
	FileFlags uint32 `json:"file_flags"`
	// FileOS represents the operating system for which this file was designed.
	FileOS uint32 `json:"file_os"`
	// FileType describes the general type of file.
	FileType uint32 `json:"file_type"`
	// FileSubtype specifies the function of the file. The possible values depend on the value of FileType.
	FileSubtype uint32 `json:"file_subtype"`
	// FileDateMS are the most significant 32 bits of the file's 64-bit binary creation date and time stamp.
	FileDateMS uint32 `json:"file_date_ms"`
	// FileDateLS are the least significant 32 bits of the file's 64-bit binary creation date and time stamp.
	FileDateLS uint32 `json:"file_date_ls"`
}

// Size returns the size of this structure in bytes.
func (f *VsFixedFileInfo) Size() uint32 { return uint32(binary.Size(f)) }

func (f *VsFixedFileInfo) GetStringFileInfoOffset(e ResourceDirectoryEntry) uint32 {
	return alignDword(VsVersionInfoStringLength+uint32(2*len(VsVersionInfoString)+1)+f.Size(), e.Data.Struct.OffsetToData)
}

func (f *VsFixedFileInfo) GetOffset(e ResourceDirectoryEntry, pe *File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + VsVersionInfoStringLength
	offset += uint32(2*len(VsVersionInfoString)) + 1
	return alignDword(offset, e.Data.Struct.OffsetToData)
}

func (pe *File) parseFixedFileInfo(e ResourceDirectoryEntry) (*VsFixedFileInfo, error) {
	var f VsFixedFileInfo
	offset := f.GetOffset(e, pe)
	b, err := pe.ReadBytesAtOffset(offset, f.Size())
	if err != nil {
		return nil, err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &f); err != nil {
		return nil, err
	}
	if f.Signature != VsFileInfoSignature {
		return nil, fmt.Errorf("invalid file info signature %d", f.Signature)
	}
	return &f, nil
}

// StringFileInfo represents the organization of data in a
// file-version resource. It contains version information
// that can be displayed for a particular language and code page.
type StringFileInfo struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func (s *StringFileInfo) GetStringTableOffset(offset uint32) uint32 {
	return offset + StringFileInfoLength + uint32(2*len(StringFileInfoString)) + 1
}

func (s *StringFileInfo) GetOffset(rva uint32, e ResourceDirectoryEntry, pe *File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	return alignDword(offset, e.Data.Struct.OffsetToData)
}

func (pe *File) parseStringFileInfo(rva uint32, e ResourceDirectoryEntry) (*StringFileInfo, string, error) {
	var s StringFileInfo
	offset := s.GetOffset(rva, e, pe)
	b, err := pe.ReadBytesAtOffset(offset, StringFileInfoLength)
	if err != nil {
		return nil, "", err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &s); err != nil {
		return nil, "", err
	}
	b, err = pe.ReadBytesAtOffset(offset+StringFileInfoLength, uint32(len(StringFileInfoString)*2)+1)
	if err != nil {
		return nil, "", err
	}
	str, err := DecodeUTF16String(b)
	return &s, str, err
}

// StringTable represents the organization of data in a
// file-version resource. It contains language and code
// page formatting information for the version strings
type StringTable struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func (s *StringTable) GetStringOffset(offset uint32, e ResourceDirectoryEntry) uint32 {
	return alignDword(offset+StringTableLength+LangIDLength, e.Data.Struct.OffsetToData)
}

func (s *StringTable) GetOffset(rva uint32, e ResourceDirectoryEntry, pe *File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	return alignDword(offset, e.Data.Struct.OffsetToData)
}

func (pe *File) parseStringTable(rva uint32, e ResourceDirectoryEntry) (*StringTable, error) {
	var s StringTable
	offset := s.GetOffset(rva, e, pe)
	b, err := pe.ReadBytesAtOffset(offset, StringTableLength)
	if err != nil {
		return nil, err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &s); err != nil {
		return nil, err
	}
	// Read the 8-digit hexadecimal number stored as a Unicode string.
	// The four most significant digits represent the language identifier.
	// The four least significant digits represent the code page for which
	// the data is formatted.
	b, err = pe.ReadBytesAtOffset(offset+StringTableLength, (8*2)+1)
	if err != nil {
		return nil, err
	}
	langID, err := DecodeUTF16String(b)
	if err != nil {
		return nil, err
	}
	if len(langID) != int(LangIDLength/2) {
		return nil, fmt.Errorf("invalid language identifier length. Expected: %d, Got: %d",
			LangIDLength/2,
			len(langID))
	}
	return &s, nil
}

// String Represents the organization of data in a
// file-version resource. It contains a string that
// describes a specific aspect of a file, for example,
// a file's version, its copyright notices, or its trademarks.
type String struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func (s *String) GetOffset(rva uint32, e ResourceDirectoryEntry, pe *File) uint32 {
	offset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	return alignDword(offset, e.Data.Struct.OffsetToData)
}

// variant of GetOffset which also returns the number of bytes which were added
// to achieve 32-bit alignment. The padding value needs to be added to the
// string length to figure out the offset of the next string
func (s *String) getOffsetAndPadding(rva uint32, e ResourceDirectoryEntry, pe *File) (uint32, uint16) {
	unalignedOffset := pe.GetOffsetFromRva(e.Data.Struct.OffsetToData) + rva
	alignedOffset := alignDword(unalignedOffset, e.Data.Struct.OffsetToData)
	return alignedOffset, uint16(alignedOffset - unalignedOffset)
}

func (pe *File) parseString(rva uint32, e ResourceDirectoryEntry) (string, string, uint16, error) {
	var s String
	offset, padding := s.getOffsetAndPadding(rva, e, pe)
	b, err := pe.ReadBytesAtOffset(offset, StringLength)
	if err != nil {
		return "", "", 0, err
	}
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &s); err != nil {
		return "", "", 0, err
	}
	const maxKeySize = 100
	b, err = pe.ReadBytesAtOffset(offset+StringLength, maxKeySize)
	if err != nil {
		return "", "", 0, err
	}
	key, err := DecodeUTF16String(b)
	if err != nil {
		return "", "", 0, err
	}
	valueOffset := alignDword(uint32(2*(len(key)+1))+offset+StringLength, e.Data.Struct.OffsetToData)
	b, err = pe.ReadBytesAtOffset(valueOffset, uint32(s.Length))
	if err != nil {
		return "", "", 0, err
	}
	value, err := DecodeUTF16String(b)
	if err != nil {
		return "", "", 0, err
	}
	// The caller of this function uses the string length as an offset to find
	// the next string in the file. We need add the alignment padding here
	// since the caller is unaware of the byte alignment, and will add the
	// string length to the unaligned offset to get the address of the next
	// string.
	totalLength := s.Length + padding
	return key, value, totalLength, nil
}

// ParseVersionResources parses file version strings from the version resource
// directory. This directory contains several structures starting with VS_VERSION_INFO
// with references to children StringFileInfo structures. In addition, StringFileInfo
// contains the StringTable structure with String entries describing the name and value
// of each file version strings.
func (pe *File) ParseVersionResources() (map[string]string, error) {
	vers := make(map[string]string)
	if pe.opts.OmitResourceDirectory {
		return vers, nil
	}
	for _, e := range pe.Resources.Entries {
		if e.ID != VersionResourceType {
			continue
		}

		directory := e.Directory.Entries[0].Directory

		for _, e := range directory.Entries {
			ver, err := pe.parseVersionInfo(e)
			if err != nil {
				return vers, err
			}
			ff, err := pe.parseFixedFileInfo(e)
			if err != nil {
				return vers, err
			}

			offset := ff.GetStringFileInfoOffset(e)

			for {
				f, n, err := pe.parseStringFileInfo(offset, e)
				if err != nil || f.Length == 0 {
					break
				}

				switch n {
				case StringFileInfoString:
					tableOffset := f.GetStringTableOffset(offset)
					for {
						table, err := pe.parseStringTable(tableOffset, e)
						if err != nil {
							break
						}
						stringOffset := table.GetStringOffset(tableOffset, e)
						for stringOffset < tableOffset+uint32(table.Length) {
							k, v, l, err := pe.parseString(stringOffset, e)
							if err != nil {
								break
							}
							vers[k] = v
							if l == 0 {
								stringOffset = tableOffset + uint32(table.Length)
							} else {
								stringOffset = stringOffset + uint32(l)
							}
						}
						// handle potential infinite loops
						if uint32(table.Length)+tableOffset > tableOffset {
							break
						}
						if tableOffset > uint32(f.Length) {
							break
						}
					}
				case VarFileInfoString:
					break
				default:
					break
				}

				offset += uint32(f.Length)

				// StringFileInfo/VarFileinfo structs consumed?
				if offset >= uint32(ver.Length) {
					break
				}
			}
		}
	}
	return vers, nil
}

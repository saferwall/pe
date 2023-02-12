// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

// TLSDirectoryCharacteristicsType represents the type of a TLS directory
// Characteristics.
type TLSDirectoryCharacteristicsType uint32

// TLSDirectory represents tls directory information with callback entries.
type TLSDirectory struct {

	// of type *IMAGE_TLS_DIRECTORY32 or *IMAGE_TLS_DIRECTORY64 structure.
	Struct interface{} `json:"struct"`

	// of type []uint32 or []uint64.
	Callbacks interface{} `json:"callbacks"`
}

// ImageTLSDirectory32 represents the IMAGE_TLS_DIRECTORY32 structure.
// It Points to the Thread Local Storage initialization section.
type ImageTLSDirectory32 struct {

	// The starting address of the TLS template. The template is a block of data
	// that is used to initialize TLS data.
	StartAddressOfRawData uint32 `json:"start_address_of_raw_data"`

	// The address of the last byte of the TLS, except for the zero fill.
	// As with the Raw Data Start VA field, this is a VA, not an RVA.
	EndAddressOfRawData uint32 `json:"end_address_of_raw_data"`

	// The location to receive the TLS index, which the loader assigns. This
	// location is in an ordinary data section, so it can be given a symbolic
	// name that is accessible to the program.
	AddressOfIndex uint32 `json:"address_of_index"`

	// The pointer to an array of TLS callback functions. The array is
	// null-terminated, so if no callback function is supported, this field
	// points to 4 bytes set to zero.
	AddressOfCallBacks uint32 `json:"address_of_callbacks"`

	// The size in bytes of the template, beyond the initialized data delimited
	// by the Raw Data Start VA and Raw Data End VA fields. The total template
	// size should be the same as the total size of TLS data in the image file.
	// The zero fill is the amount of data that comes after the initialized
	// nonzero data.
	SizeOfZeroFill uint32 `json:"size_of_zero_fill"`

	// The four bits [23:20] describe alignment info. Possible values are those
	// defined as IMAGE_SCN_ALIGN_*, which are also used to describe alignment
	// of section in object files. The other 28 bits are reserved for future use.
	Characteristics TLSDirectoryCharacteristicsType `json:"characteristics"`
}

// ImageTLSDirectory64 represents the IMAGE_TLS_DIRECTORY64 structure.
// It Points to the Thread Local Storage initialization section.
type ImageTLSDirectory64 struct {
	// The starting address of the TLS template. The template is a block of data
	// that is used to initialize TLS data.
	StartAddressOfRawData uint64 `json:"start_address_of_raw_data"`

	// The address of the last byte of the TLS, except for the zero fill. As
	// with the Raw Data Start VA field, this is a VA, not an RVA.
	EndAddressOfRawData uint64 `json:"end_address_of_raw_data"`

	// The location to receive the TLS index, which the loader assigns. This
	// location is in an ordinary data section, so it can be given a symbolic
	// name that is accessible to the program.
	AddressOfIndex uint64 `json:"address_of_index"`

	// The pointer to an array of TLS callback functions. The array is
	// null-terminated, so if no callback function is supported, this field
	// points to 4 bytes set to zero.
	AddressOfCallBacks uint64 `json:"address_of_callbacks"`

	// The size in bytes of the template, beyond the initialized data delimited
	// by the Raw Data Start VA and Raw Data End VA fields. The total template
	// size should be the same as the total size of TLS data in the image file.
	// The zero fill is the amount of data that comes after the initialized
	// nonzero data.
	SizeOfZeroFill uint32 `json:"size_of_zero_fill"`

	// The four bits [23:20] describe alignment info. Possible values are those
	// defined as IMAGE_SCN_ALIGN_*, which are also used to describe alignment
	// of section in object files. The other 28 bits are reserved for future use.
	Characteristics TLSDirectoryCharacteristicsType `json:"characteristics"`
}

// TLS provides direct PE and COFF support for static thread local storage (TLS).
// TLS is a special storage class that Windows supports in which a data object
// is not an automatic (stack) variable, yet is local to each individual thread
// that runs the code. Thus, each thread can maintain a different value for a
// variable declared by using TLS.
func (pe *File) parseTLSDirectory(rva, size uint32) error {

	tls := TLSDirectory{}

	if pe.Is64 {
		tlsDir := ImageTLSDirectory64{}
		tlsSize := uint32(binary.Size(tlsDir))
		fileOffset := pe.GetOffsetFromRva(rva)
		err := pe.structUnpack(&tlsDir, fileOffset, tlsSize)
		if err != nil {
			return err
		}
		tls.Struct = tlsDir

		if tlsDir.AddressOfCallBacks != 0 {
			var callbacks []uint64
			rvaAddressOfCallBacks := uint32(tlsDir.AddressOfCallBacks -
				pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase)
			offset := pe.GetOffsetFromRva(rvaAddressOfCallBacks)
			for {
				c, err := pe.ReadUint64(offset)
				if err != nil || c == 0 {
					break
				}
				callbacks = append(callbacks, c)
				offset += 8
			}
			tls.Callbacks = callbacks
		}
	} else {
		tlsDir := ImageTLSDirectory32{}
		tlsSize := uint32(binary.Size(tlsDir))
		fileOffset := pe.GetOffsetFromRva(rva)
		err := pe.structUnpack(&tlsDir, fileOffset, tlsSize)
		if err != nil {
			return err
		}
		tls.Struct = tlsDir

		// 94a9dc17d47b03f6fb01cb639e25503b37761b452e7c07ec6b6c2280635f1df9
		// Callbacks may be empty.
		if tlsDir.AddressOfCallBacks != 0 {
			var callbacks []uint32
			rvaAddressOfCallBacks := tlsDir.AddressOfCallBacks -
				pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
			offset := pe.GetOffsetFromRva(rvaAddressOfCallBacks)
			for {
				c, err := pe.ReadUint32(offset)
				if err != nil || c == 0 {
					break
				}
				callbacks = append(callbacks, c)
				offset += 4
			}
			tls.Callbacks = callbacks
		}
	}

	pe.TLS = tls
	pe.HasTLS = true
	return nil
}

// String returns the string representations of the `Characteristics` field of
// TLS directory.
func (characteristics TLSDirectoryCharacteristicsType) String() string {

	m := map[TLSDirectoryCharacteristicsType]string{
		ImageSectionAlign1Bytes:    "Align 1-Byte",
		ImageSectionAlign2Bytes:    "Align 2-Bytes",
		ImageSectionAlign4Bytes:    "Align 4-Bytes",
		ImageSectionAlign8Bytes:    "Align 8-Bytes",
		ImageSectionAlign16Bytes:   "Align 16-Bytes",
		ImageSectionAlign32Bytes:   "Align 32-Bytes",
		ImageSectionAlign64Bytes:   "Align 64-Bytes",
		ImageSectionAlign128Bytes:  "Align 128-Bytes",
		ImageSectionAlign256Bytes:  "Align 265-Bytes",
		ImageSectionAlign512Bytes:  "Align 512-Bytes",
		ImageSectionAlign1024Bytes: "Align 1024-Bytes",
		ImageSectionAlign2048Bytes: "Align 2048-Bytes",
		ImageSectionAlign4096Bytes: "Align 4096-Bytes",
		ImageSectionAlign8192Bytes: "Align 8192-Bytes",
	}

	v, ok := m[characteristics]
	if ok {
		return v
	}

	return "?"
}

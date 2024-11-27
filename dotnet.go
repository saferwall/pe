// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

// References
// https://www.ntcore.com/files/dotnetformat.htm

// COMImageFlagsType represents a COM+ header entry point flag type.
type COMImageFlagsType uint32

// COM+ Header entry point flags.
const (
	// The image file contains IL code only, with no embedded native unmanaged
	// code except the start-up stub (which simply executes an indirect jump to
	// the CLR entry point).
	COMImageFlagsILOnly = 0x00000001

	// The image file can be loaded only into a 32-bit process.
	COMImageFlags32BitRequired = 0x00000002

	// This flag is obsolete and should not be set. Setting it—as the IL
	// assembler allows, using the .corflags directive—will render your module
	// un-loadable.
	COMImageFlagILLibrary = 0x00000004

	// The image file is protected with a strong name signature.
	COMImageFlagsStrongNameSigned = 0x00000008

	// The executable’s entry point is an unmanaged method. The EntryPointToken/
	// EntryPointRVA field of the CLR header contains the RVA of this native
	// method. This flag was introduced in version 2.0 of the CLR.
	COMImageFlagsNativeEntrypoint = 0x00000010

	// The CLR loader and the JIT compiler are required to track debug
	// information about the methods. This flag is not used.
	COMImageFlagsTrackDebugData = 0x00010000

	// The image file can be loaded into any process, but preferably into a
	// 32-bit process. This flag can be only set together with flag
	// COMIMAGE_FLAGS_32BITREQUIRED. When set, these two flags mean the image
	// is platformneutral, but prefers to be loaded as 32-bit when possible.
	// This flag was introduced in CLR v4.0
	COMImageFlags32BitPreferred = 0x00020000
)

// V-table constants.
const (
	// V-table slots are 32-bits in size.
	CORVTable32Bit = 0x01

	// V-table slots are 64-bits in size.
	CORVTable64Bit = 0x02

	//  The thunk created by the common language runtime must provide data
	// marshaling between managed and unmanaged code.
	CORVTableFromUnmanaged = 0x04

	// The thunk created by the common language runtime must provide data
	// marshaling between managed and unmanaged code. Current appdomain should
	// be selected to dispatch the call.
	CORVTableFromUnmanagedRetainAppDomain = 0x08

	// Call most derived method described by
	CORVTableCallMostDerived = 0x10
)

// Metadata Tables constants.
const (
	// The current module descriptor.
	Module = 0
	// Class reference descriptors.
	TypeRef = 1
	// Class or interface definition descriptors.
	TypeDef = 2
	// A class-to-fields lookup table, which does not exist in optimized
	// metadata (#~ stream).
	FieldPtr = 3
	// Field definition descriptors.
	Field = 4
	// A class-to-methods lookup table, which does not exist in
	// optimized metadata (#~ stream).
	MethodPtr = 5
	// Method definition descriptors.
	MethodDef = 6
	// A method-to-parameters lookup table, which does not exist in optimized
	// metadata (#~ stream).
	ParamPtr = 7
	// Parameter definition descriptors.
	Param = 8
	// Interface implementation descriptors.
	InterfaceImpl = 9
	// Member (field or method) reference descriptors.
	MemberRef = 10
	// Constant value descriptors that map the default values stored in the
	// #Blob stream to respective fields, parameters, and properties.
	Constant = 11
	// Custom attribute descriptors.
	CustomAttribute = 12
	// Field or parameter marshaling descriptors for managed/unmanaged
	// inter-operations.
	FieldMarshal = 13
	// Security descriptors.
	DeclSecurity = 14
	// Class layout descriptors that hold information about how the loader
	// should lay out respective classes.
	ClassLayout = 15
	// Field layout descriptors that specify the offset or ordinal of
	// individual fields.
	FieldLayout = 16
	// Stand-alone signature descriptors. Signatures per se are used in two
	// capacities: as composite signatures of local variables of methods and as
	// parameters of the call indirect (calli) IL instruction.
	StandAloneSig = 17
	// A class-to-events mapping table. This is not an intermediate lookup
	// table, and it does exist in optimized metadata.
	EventMap = 18
	// An event map–to–events lookup table, which does not exist in optimized
	// metadata (#~ stream).
	EventPtr = 19
	// Event descriptors.
	Event = 20
	// A class-to-properties mapping table. This is not an intermediate lookup
	// table, and it does exist in optimized metadata.
	PropertyMap = 21
	// A property map–to–properties lookup table, which does not exist in
	// optimized metadata (#~ stream).
	PropertyPtr = 22
	// Property descriptors.
	Property = 23
	// Method semantics descriptors that hold information about which method is
	// associated with a specific property or event and in what capacity.
	MethodSemantics = 24
	// Method implementation descriptors.
	MethodImpl = 25
	// Module reference descriptors.
	ModuleRef = 26
	// Type specification descriptors.
	TypeSpec = 27
	// Implementation map descriptors used for the platform invocation
	// (P/Invoke) type of managed/unmanaged code inter-operation.
	ImplMap = 28
	// Field-to-data mapping descriptors.
	FieldRVA = 29
	// Edit-and-continue log descriptors that hold information about what
	// changes have been made to specific metadata items during in-memory
	// editing. This table does not exist in optimized metadata (#~ stream)
	ENCLog = 30
	// Edit-and-continue mapping descriptors. This table does not exist in
	// optimized metadata (#~ stream).
	ENCMap = 31
	// The current assembly descriptor, which should appear only in the prime
	// module metadata.
	Assembly = 32
	// This table is unused.
	AssemblyProcessor = 33
	// This table is unused.
	AssemblyOS = 34
	// Assembly reference descriptors.
	AssemblyRef = 35
	// This table is unused.
	AssemblyRefProcessor = 36
	// This table is unused.
	AssemblyRefOS = 37
	// File descriptors that contain information about other files in the
	// current assembly.
	FileMD = 38
	// Exported type descriptors that contain information about public classes
	// exported by the current assembly, which are declared in other modules of
	// the assembly. Only the prime module of the assembly should carry this
	// table.
	ExportedType = 39
	// Managed resource descriptors.
	ManifestResource = 40
	// Nested class descriptors that provide mapping of nested classes to their
	// respective enclosing classes.
	NestedClass = 41
	//  Type parameter descriptors for generic (parameterized) classes and
	// methods.
	GenericParam = 42
	// Generic method instantiation descriptors.
	MethodSpec = 43
	// Descriptors of constraints specified for type parameters of generic
	// classes and methods
	GenericParamConstraint = 44
)

// Heaps Streams Bit Positions.
const (
	StringStream = 0
	GUIDStream   = 1
	BlobStream   = 2
)

// MetadataTableIndexToString returns the string representation of the metadata
// table index.
func MetadataTableIndexToString(k int) string {
	metadataTablesMap := map[int]string{
		Module:                 "Module",
		TypeRef:                "TypeRef",
		TypeDef:                "TypeDef",
		FieldPtr:               "FieldPtr",
		Field:                  "Field",
		MethodPtr:              "MethodPtr",
		MethodDef:              "MethodDef",
		ParamPtr:               "ParamPtr",
		Param:                  "Param",
		InterfaceImpl:          "InterfaceImpl",
		MemberRef:              "MemberRef",
		Constant:               "Constant",
		CustomAttribute:        "CustomAttribute",
		FieldMarshal:           "FieldMarshal",
		DeclSecurity:           "DeclSecurity",
		ClassLayout:            "ClassLayout",
		FieldLayout:            "FieldLayout",
		StandAloneSig:          "StandAloneSig",
		EventMap:               "EventMap",
		EventPtr:               "EventPtr",
		Event:                  "Event",
		PropertyMap:            "PropertyMap",
		PropertyPtr:            "PropertyPtr",
		Property:               "Property",
		MethodSemantics:        "MethodSemantics",
		MethodImpl:             "MethodImpl",
		ModuleRef:              "ModuleRef",
		TypeSpec:               "TypeSpec",
		ImplMap:                "ImplMap",
		FieldRVA:               "FieldRVA",
		ENCLog:                 "ENCLog",
		ENCMap:                 "ENCMap",
		Assembly:               "Assembly",
		AssemblyProcessor:      "AssemblyProcessor",
		AssemblyOS:             "AssemblyOS",
		AssemblyRef:            "AssemblyRef",
		AssemblyRefProcessor:   "AssemblyRefProcessor",
		AssemblyRefOS:          "AssemblyRefOS",
		FileMD:                 "File",
		ExportedType:           "ExportedType",
		ManifestResource:       "ManifestResource",
		NestedClass:            "NestedClass",
		GenericParam:           "GenericParam",
		MethodSpec:             "MethodSpec",
		GenericParamConstraint: "GenericParamConstraint",
	}

	if value, ok := metadataTablesMap[k]; ok {
		return value
	}
	return ""
}

// GetMetadataStreamIndexSize returns the size of indexes to read into a
// particular heap.
func (pe *File) GetMetadataStreamIndexSize(BitPosition int) int {
	// The `Heaps` field is a bit vector that encodes how wide indexes into the
	// various heaps are:
	// - If bit 0 is set, indexes into the "#String" heap are 4 bytes wide;
	// - if bit 1 is set, indexes into the "#GUID" heap are 4 bytes wide;
	// - if bit 2 is set, indexes into the "#Blob" heap are 4 bytes wide.
	heaps := pe.CLR.MetadataTablesStreamHeader.Heaps
	if IsBitSet(uint64(heaps), BitPosition) {
		return 4
	}
	// Conversely, if the HeapSizes bit for a particular heap is not set,
	// indexes into that heap are 2 bytes wide.
	return 2
}

// ImageDataDirectory represents the  directory format.
type ImageDataDirectory struct {

	// The relative virtual address of the table.
	VirtualAddress uint32 `json:"virtual_address"`

	// The size of the table, in bytes.
	Size uint32 `json:"size"`
}

// ImageCOR20Header represents the CLR 2.0 header structure.
type ImageCOR20Header struct {

	// Size of the header in bytes.
	Cb uint32 `json:"cb"`

	// Major number of the minimum version of the runtime required to run the
	// program.
	MajorRuntimeVersion uint16 `json:"major_runtime_version"`

	// Minor number of the version of the runtime required to run the program.
	MinorRuntimeVersion uint16 `json:"minor_runtime_version"`

	// RVA and size of the metadata.
	MetaData ImageDataDirectory `json:"meta_data"`

	// Bitwise flags indicating attributes of this executable.
	Flags COMImageFlagsType `json:"flags"`

	// Metadata identifier (token) of the entry point for the image file; can
	// be 0 for DLL images. This field identifies a method belonging to this
	// module or a module containing the entry point method.
	// In images of version 2.0 and newer, this field may contain RVA of the
	// embedded native entry point method.
	// union {
	//
	// If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is not set,
	// EntryPointToken represents a managed entrypoint.
	//	DWORD               EntryPointToken;
	//
	// If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set,
	// EntryPointRVA represents an RVA to a native entrypoint
	//	DWORD               EntryPointRVA;
	//};
	EntryPointRVAorToken uint32 `json:"entry_point_rva_or_token"`

	// This is the blob of managed resources. Fetched using
	// code:AssemblyNative.GetResource and code:PEFile.GetResource and accessible
	// from managed code from System.Assembly.GetManifestResourceStream. The
	// metadata has a table that maps names to offsets into this blob, so
	// logically the blob is a set of resources.
	Resources ImageDataDirectory `json:"resources"`

	// RVA and size of the hash data for this PE file, used by the loader for
	// binding and versioning. IL assemblies can be signed with a public-private
	// key to validate who created it. The signature goes here if this feature
	// is used.
	StrongNameSignature ImageDataDirectory `json:"strong_name_signature"`

	// RVA and size of the Code Manager table. In the existing releases of the
	// runtime, this field is reserved and must be set to 0.
	CodeManagerTable ImageDataDirectory `json:"code_manager_table"`

	// RVA and size in bytes of an array of virtual table (v-table) fixups.
	// Among current managed compilers, only the VC++ linker and the IL
	// assembler can produce this array.
	VTableFixups ImageDataDirectory `json:"vtable_fixups"`

	// RVA and size of an array of addresses of jump thunks. Among managed
	// compilers, only the VC++ of versions pre-8.0 could produce this table,
	// which allows the export of unmanaged native methods embedded in the
	// managed PE file. In v2.0+ of CLR this entry is obsolete and must be set
	// to 0.
	ExportAddressTableJumps ImageDataDirectory `json:"export_address_table_jumps"`

	// Reserved for precompiled images; set to 0
	// NGEN images it points at a code:CORCOMPILE_HEADER structure
	ManagedNativeHeader ImageDataDirectory `json:"managed_native_header"`
}

// ImageCORVTableFixup defines the v-table fixups that contains the
// initializing information necessary for the runtime to create the thunks.
// Non VOS v-table entries.  Define an array of these pointed to by
// IMAGE_COR20_HEADER.VTableFixups.  Each entry describes a contiguous array of
// v-table slots.  The slots start out initialized to the meta data token value
// for the method they need to call.  At image load time, the CLR Loader will
// turn each entry into a pointer to machine code for the CPU and can be
// called directly.
type ImageCORVTableFixup struct {
	RVA   uint32 `json:"rva"`   // Offset of v-table array in image.
	Count uint16 `json:"count"` // How many entries at location.
	Type  uint16 `json:"type"`  // COR_VTABLE_xxx type of entries.
}

// MetadataHeader consists of a storage signature and a storage header.
type MetadataHeader struct {

	// The storage signature, which must be 4-byte aligned:
	// ”Magic” signature for physical metadata, currently 0x424A5342, or, read
	// as characters, BSJB—the initials of four “founding fathers” Brian Harry,
	// Susa Radke-Sproull, Jason Zander, and Bill Evans, who started the
	// runtime development in 1998.
	Signature uint32 `json:"signature"`

	// Major version.
	MajorVersion uint16 `json:"major_version"`

	// Minor version.
	MinorVersion uint16 `json:"minor_version"`

	// Reserved; set to 0.
	ExtraData uint32 `json:"extra_data"`

	// Length of the version string.
	VersionString uint32 `json:"version_string"`

	// Version string.
	Version string `json:"version"`

	// The storage header follows the storage signature, aligned on a 4-byte
	// boundary.
	//

	// Reserved; set to 0.
	Flags uint8 `json:"flags"`

	// Another byte used for [padding]

	// Number of streams.
	Streams uint16 `json:"streams"`
}

// MetadataStreamHeader represents a Metadata Stream Header Structure.
type MetadataStreamHeader struct {
	// Offset in the file for this stream.
	Offset uint32 `json:"offset"`

	// Size of the stream in bytes.
	Size uint32 `json:"size"`

	// Name of the stream; a zero-terminated ASCII string no longer than 31
	// characters (plus zero terminator). The name might be shorter, in which
	// case the size of the stream header is correspondingly reduced, padded to
	// the 4-byte boundary.
	Name string `json:"name"`
}

// MetadataTableStreamHeader represents the Metadata Table Stream Header Structure.
type MetadataTableStreamHeader struct {
	// Reserved; set to 0.
	Reserved uint32 `json:"reserved"`

	// Major version of the table schema (1 for v1.0 and v1.1; 2 for v2.0 or later).
	MajorVersion uint8 `json:"major_version"`

	// Minor version of the table schema (0 for all versions).
	MinorVersion uint8 `json:"minor_version"`

	// Binary flags indicate the offset sizes to be used within the heaps.
	// 4-byte unsigned integer offset is indicated by:
	// - 0x01 for a string heap, 0x02 for a GUID heap, and 0x04 for a blob heap.
	// If a flag is not set, the respective heap offset is a 2-byte unsigned integer.
	// A #- stream can also have special flags set:
	// - flag 0x20, indicating that the stream contains only changes made
	// during an edit-and-continue session, and;
	// - flag 0x80, indicating that the  metadata might contain items marked as
	// deleted.
	Heaps uint8 `json:"heaps"`

	// Bit width of the maximal record index to all tables of the metadata;
	// calculated at run time (during the metadata stream initialization).
	RID uint8 `json:"rid"`

	// Bit vector of present tables, each bit representing one table (1 if
	// present).
	MaskValid uint64 `json:"mask_valid"`

	// Bit vector of sorted tables, each bit representing a respective table (1
	// if sorted)
	Sorted uint64 `json:"sorted"`
}

// MetadataTable represents the content of a particular table in the metadata.
// The metadata schema defines 45 tables.
type MetadataTable struct {
	// The name of the table.
	Name string `json:"name"`

	// Number of columns in the table.
	CountCols uint32 `json:"count_cols"`

	// Every table has a different layout, defined in the ECMA-335 spec.
	// Content abstract the type each table is pointing to.
	Content interface{} `json:"content"`
}

// CLRData embeds the Common Language Runtime Header structure as well as the
// Metadata header structure.
type CLRData struct {
	CLRHeader                  ImageCOR20Header          `json:"clr_header"`
	MetadataHeader             MetadataHeader            `json:"metadata_header"`
	MetadataStreamHeaders      []MetadataStreamHeader    `json:"metadata_stream_headers"`
	MetadataStreams            map[string][]byte         `json:"-"`
	MetadataTablesStreamHeader MetadataTableStreamHeader `json:"metadata_tables_stream_header"`
	MetadataTables             map[int]*MetadataTable    `json:"metadata_tables"`
	StringStreamIndexSize      int                       `json:"-"`
	GUIDStreamIndexSize        int                       `json:"-"`
	BlobStreamIndexSize        int                       `json:"-"`
}

func (pe *File) parseMetadataStream(off, size uint32) (MetadataTableStreamHeader, error) {

	mdTableStreamHdr := MetadataTableStreamHeader{}
	if size == 0 {
		return mdTableStreamHdr, nil
	}

	mdTableStreamHdrSize := uint32(binary.Size(mdTableStreamHdr))
	err := pe.structUnpack(&mdTableStreamHdr, off, mdTableStreamHdrSize)
	if err != nil {
		return mdTableStreamHdr, err
	}

	return mdTableStreamHdr, nil
}

func (pe *File) parseMetadataHeader(offset, size uint32) (MetadataHeader, error) {
	var err error
	mh := MetadataHeader{}

	if mh.Signature, err = pe.ReadUint32(offset); err != nil {
		return mh, err
	}
	if mh.MajorVersion, err = pe.ReadUint16(offset + 4); err != nil {
		return mh, err
	}
	if mh.MinorVersion, err = pe.ReadUint16(offset + 6); err != nil {
		return mh, err
	}
	if mh.ExtraData, err = pe.ReadUint32(offset + 8); err != nil {
		return mh, err
	}
	if mh.VersionString, err = pe.ReadUint32(offset + 12); err != nil {
		return mh, err
	}
	mh.Version, err = pe.getStringAtOffset(offset+16, mh.VersionString)
	if err != nil {
		return mh, err
	}

	offset += 16 + mh.VersionString
	if mh.Flags, err = pe.ReadUint8(offset); err != nil {
		return mh, err
	}

	if mh.Streams, err = pe.ReadUint16(offset + 2); err != nil {
		return mh, err
	}

	return mh, err
}

// The 15th directory entry of the PE header contains the RVA and size of the
// runtime header in the image file. The runtime header, which contains all of
// the runtime-specific data entries and other information, should reside in a
// read-only section of the image file. The IL assembler puts the common
// language runtime header in the .text section.
func (pe *File) parseCLRHeaderDirectory(rva, size uint32) error {

	clrHeader := ImageCOR20Header{}
	offset := pe.GetOffsetFromRva(rva)
	err := pe.structUnpack(&clrHeader, offset, size)
	if err != nil {
		return err
	}

	pe.CLR.CLRHeader = clrHeader
	if clrHeader.MetaData.VirtualAddress == 0 || clrHeader.MetaData.Size == 0 {
		return nil
	}

	// If we get a CLR header, we assume that this is enough
	// to say we have a CLR data to show even if parsing
	// other structures fails later.
	pe.HasCLR = true

	if pe.opts.OmitCLRMetadata {
		return nil
	}

	offset = pe.GetOffsetFromRva(clrHeader.MetaData.VirtualAddress)
	mh, err := pe.parseMetadataHeader(offset, clrHeader.MetaData.Size)
	if err != nil {
		return err
	}
	pe.CLR.MetadataHeader = mh
	pe.CLR.MetadataStreams = make(map[string][]byte)
	offset += 16 + mh.VersionString + 4

	// Immediately following the MetadataHeader is a series of Stream Headers.
	// A “stream” is to the metadata what a “section” is to the assembly. The
	// NumberOfStreams property indicates how many StreamHeaders to read.
	mdStreamHdrOff := uint32(0)
	mdStreamHdrSize := uint32(0)
	for i := uint16(0); i < mh.Streams; i++ {
		sh := MetadataStreamHeader{}
		if sh.Offset, err = pe.ReadUint32(offset); err != nil {
			return err
		}
		if sh.Size, err = pe.ReadUint32(offset + 4); err != nil {
			return err
		}

		// Name requires a special treatment.
		offset += 8
		for j := uint32(0); j <= 32; j++ {
			var c uint8
			if c, err = pe.ReadUint8(offset); err != nil {
				return err
			}

			offset++
			if c == 0 && (j+1)%4 == 0 {
				break
			}
			if c != 0 {
				sh.Name += string(c)
			}
		}

		// The streams #~ and #- are mutually exclusive; that is, the metadata
		// structure of the module is either optimized or un-optimized; it
		// cannot be both at the same time or be something in between.
		if sh.Name == "#~" || sh.Name == "#-" {
			mdStreamHdrOff = sh.Offset
			mdStreamHdrSize = sh.Size
		}

		// Save the stream into a map <string> []byte.
		rva = clrHeader.MetaData.VirtualAddress + sh.Offset
		start := pe.GetOffsetFromRva(rva)
		pe.CLR.MetadataStreams[sh.Name] = pe.data[start : start+sh.Size]
		pe.CLR.MetadataStreamHeaders = append(pe.CLR.MetadataStreamHeaders, sh)
	}

	// Get the Metadata Table Stream.
	if mdStreamHdrSize == 0 {
		return nil
	}
	// The .Offset indicated by the stream header is an RVA relative to the
	// metadataDirectoryAddress in the CLRHeader.
	rva = clrHeader.MetaData.VirtualAddress + mdStreamHdrOff
	offset = pe.GetOffsetFromRva(rva)
	mdTableStreamHdr, err := pe.parseMetadataStream(offset, mdStreamHdrSize)
	if err != nil {
		return nil
	}
	pe.CLR.MetadataTablesStreamHeader = mdTableStreamHdr

	// Get the size of indexes of #String", "#GUID" and "#Blob" streams.
	pe.CLR.StringStreamIndexSize = pe.GetMetadataStreamIndexSize(StringStream)
	pe.CLR.GUIDStreamIndexSize = pe.GetMetadataStreamIndexSize(GUIDStream)
	pe.CLR.BlobStreamIndexSize = pe.GetMetadataStreamIndexSize(BlobStream)

	// This header is followed by a sequence of 4-byte unsigned integers
	// indicating the number of records in each table marked 1 in the MaskValid
	// bit vector.
	offset += uint32(binary.Size(mdTableStreamHdr))
	pe.CLR.MetadataTables = make(map[int]*MetadataTable)
	for i := 0; i <= GenericParamConstraint; i++ {
		if IsBitSet(mdTableStreamHdr.MaskValid, i) {
			mdTable := MetadataTable{}
			mdTable.Name = MetadataTableIndexToString(i)
			mdTable.CountCols, err = pe.ReadUint32(offset)
			if err != nil {
				break
			}
			offset += 4
			pe.CLR.MetadataTables[i] = &mdTable
		}
	}

	// Parse the metadata tables.
	for tableIndex := 0; tableIndex <= GenericParamConstraint; tableIndex++ {
		table, ok := pe.CLR.MetadataTables[tableIndex]
		if !ok {
			continue
		}

		n := uint32(0)
		switch tableIndex {
		case Module: // 0x00
			table.Content, n, err = pe.parseMetadataModuleTable(offset)
		case TypeRef: // 0x01
			table.Content, n, err = pe.parseMetadataTypeRefTable(offset)
		case TypeDef: // 0x02
			table.Content, n, err = pe.parseMetadataTypeDefTable(offset)
		case Field: // 0x04
			table.Content, n, err = pe.parseMetadataFieldTable(offset)
		case MethodDef: // 0x06
			table.Content, n, err = pe.parseMetadataMethodDefTable(offset)
		case Param: // 0x08
			table.Content, n, err = pe.parseMetadataParamTable(offset)
		case InterfaceImpl: // 0x09
			table.Content, n, err = pe.parseMetadataInterfaceImplTable(offset)
		case MemberRef: // 0x0a
			table.Content, n, err = pe.parseMetadataMemberRefTable(offset)
		case Constant: // 0x0b
			table.Content, n, err = pe.parseMetadataConstantTable(offset)
		case CustomAttribute: // 0x0c
			table.Content, n, err = pe.parseMetadataCustomAttributeTable(offset)
		case FieldMarshal: // 0x0d
			table.Content, n, err = pe.parseMetadataFieldMarshalTable(offset)
		case DeclSecurity: // 0x0e
			table.Content, n, err = pe.parseMetadataDeclSecurityTable(offset)
		case ClassLayout: // 0x0f
			table.Content, n, err = pe.parseMetadataClassLayoutTable(offset)
		case FieldLayout: // 0x10
			table.Content, n, err = pe.parseMetadataFieldLayoutTable(offset)
		case StandAloneSig: // 0x11
			table.Content, n, err = pe.parseMetadataStandAloneSignTable(offset)
		case EventMap: // 0x12
			table.Content, n, err = pe.parseMetadataEventMapTable(offset)
		case Event: // 0x14
			table.Content, n, err = pe.parseMetadataEventTable(offset)
		case PropertyMap: // 0x15
			table.Content, n, err = pe.parseMetadataPropertyMapTable(offset)
		case Property: // 0x17
			table.Content, n, err = pe.parseMetadataPropertyTable(offset)
		case MethodSemantics: // 0x18
			table.Content, n, err = pe.parseMetadataMethodSemanticsTable(offset)
		case MethodImpl: // 0x19
			table.Content, n, err = pe.parseMetadataMethodImplTable(offset)
		case ModuleRef: // 0x1a
			table.Content, n, err = pe.parseMetadataModuleRefTable(offset)
		case TypeSpec: // 0x1b
			table.Content, n, err = pe.parseMetadataTypeSpecTable(offset)
		case ImplMap: // 0x1c
			table.Content, n, err = pe.parseMetadataImplMapTable(offset)
		case FieldRVA: // 0x1d
			table.Content, n, err = pe.parseMetadataFieldRVATable(offset)
		case Assembly: // 0x20
			table.Content, n, err = pe.parseMetadataAssemblyTable(offset)
		case AssemblyRef: // 0x23
			table.Content, n, err = pe.parseMetadataAssemblyRefTable(offset)
		case ExportedType: // 0x27
			table.Content, n, err = pe.parseMetadataExportedTypeTable(offset)
		case ManifestResource: // 0x28
			table.Content, n, err = pe.parseMetadataManifestResourceTable(offset)
		case NestedClass: // 0x29
			table.Content, n, err = pe.parseMetadataNestedClassTable(offset)
		case GenericParam: // 0x2a
			table.Content, n, err = pe.parseMetadataGenericParamTable(offset)
		case MethodSpec: // 0x2b
			table.Content, n, err = pe.parseMetadataMethodSpecTable(offset)
		case GenericParamConstraint: // 0x2c
			table.Content, n, err = pe.parseMetadataGenericParamConstraintTable(offset)
		default:
			pe.logger.Warnf("unhandled metadata table %d %s offset 0x%x cols %d",
				tableIndex, MetadataTableIndexToString(tableIndex), offset, table.CountCols)
		}
		if err != nil {
			pe.logger.Warnf("parsing metadata table %s failed with %v",
				MetadataTableIndexToString(tableIndex), err)
		}
		offset += n

	}

	return nil
}

// String returns a string interpretation of a COMImageFlags type.
func (flags COMImageFlagsType) String() []string {
	COMImageFlags := map[COMImageFlagsType]string{
		COMImageFlagsILOnly:           "IL Only",
		COMImageFlags32BitRequired:    "32-Bit Required",
		COMImageFlagILLibrary:         "IL Library",
		COMImageFlagsStrongNameSigned: "Strong Name Signed",
		COMImageFlagsNativeEntrypoint: "Native Entrypoint",
		COMImageFlagsTrackDebugData:   "Track Debug Data",
		COMImageFlags32BitPreferred:   "32-Bit Preferred",
	}

	var values []string
	for k, v := range COMImageFlags {
		if (k & flags) == k {
			values = append(values, v)
		}
	}

	return values
}

// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

const (

	// MaxDefaultSymbolsCount represents the default maximum number of COFF
	// symbols to parse. Some malware uses a fake huge NumberOfSymbols that
	// can cause an OOM exception.
	// Example: 0000e876c5b712b6b7b3ce97f757ddd918fb3dbdc5a3938e850716fbd841309f
	MaxDefaultCOFFSymbolsCount = 0x10000

	// MaxCOFFSymStrLength represents the maximum string length of a COFF symbol
	// to read.
	MaxCOFFSymStrLength = 0x50

	//
	// Type Representation
	//

	// ImageSymTypeNull indicates no type information or unknown base type.
	// Microsoft tools use this setting.
	ImageSymTypeNull = 0

	// ImageSymTypeVoid indicates no type no valid type; used with void pointers and functions.
	ImageSymTypeVoid = 1

	// ImageSymTypeChar indicates a character (signed byte).
	ImageSymTypeChar = 2

	// ImageSymTypeShort indicates a 2-byte signed integer.
	ImageSymTypeShort = 3

	// ImageSymTypeInt indicates a natural integer type (normally 4 bytes in
	// Windows).
	ImageSymTypeInt = 4

	// ImageSymTypeLong indicates a 4-byte signed integer.
	ImageSymTypeLong = 5

	// ImageSymTypeFloat indicates a 4-byte floating-point number.
	ImageSymTypeFloat = 6

	// ImageSymTypeDouble indicates an 8-byte floating-point number.
	ImageSymTypeDouble = 7

	// ImageSymTypeStruct indicates a structure.
	ImageSymTypeStruct = 8

	// ImageSymTypeUnion indicates a union.
	ImageSymTypeUnion = 9

	// ImageSymTypeEnum indicates an enumerated type.
	ImageSymTypeEnum = 10

	// ImageSymTypeMoe A member of enumeration (a specific value).
	ImageSymTypeMoe = 11

	// ImageSymTypeByte indicates a byte; unsigned 1-byte integer.
	ImageSymTypeByte = 12

	// ImageSymTypeWord indicates a word; unsigned 2-byte integer.
	ImageSymTypeWord = 13

	// ImageSymTypeUint indicates an unsigned integer of natural size
	// (normally, 4 bytes).
	ImageSymTypeUint = 14

	// ImageSymTypeDword indicates an unsigned 4-byte integer.
	ImageSymTypeDword = 15

	//
	// Storage Class
	//

	// ImageSymClassEndOfFunction indicates a special symbol that represents
	// the end of function, for debugging purposes.
	ImageSymClassEndOfFunction = 0xff

	// ImageSymClassNull indicates no assigned storage class.
	ImageSymClassNull = 0

	// ImageSymClassAutomatic indicates automatic (stack) variable. The Value
	// field specifies the stack frame offset.
	ImageSymClassAutomatic = 1

	// ImageSymClassExternal indicates a value that Microsoft tools use for
	// external symbols. The Value field indicates the size if the section
	// number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero,
	// then the Value field specifies the offset within the section.
	ImageSymClassExternal = 2

	// ImageSymClassStatic indicates the offset of the symbol within the
	// section. If the Value field is zero, then the symbol represents a
	// section name.
	ImageSymClassStatic = 3

	// ImageSymClassRegister indicates a register variable. The Value field
	// specifies the register number.
	ImageSymClassRegister = 4

	// ImageSymClassExternalDef indicates a symbol that is defined externally.
	ImageSymClassExternalDef = 5

	// ImageSymClassLabel indicates a code label that is defined within the
	// module. The Value field specifies the offset of the symbol within the
	// section.
	ImageSymClassLabel = 6

	// ImageSymClassUndefinedLabel indicates a reference to a code label that
	// is not defined.
	ImageSymClassUndefinedLabel = 7

	// ImageSymClassMemberOfStruct indicates the structure member. The Value
	// field specifies the n th member.
	ImageSymClassMemberOfStruct = 8

	// ImageSymClassArgument indicates a formal argument (parameter) of a
	// function. The Value field specifies the n th argument.
	ImageSymClassArgument = 9

	// ImageSymClassStructTag indicates the structure tag-name entry.
	ImageSymClassStructTag = 10

	// ImageSymClassMemberOfUnion indicates a union member. The Value field
	// specifies the n th member.
	ImageSymClassMemberOfUnion = 11

	// ImageSymClassUnionTag indicates the structure tag-name entry.
	ImageSymClassUnionTag = 12

	// ImageSymClassTypeDefinition indicates a typedef entry.
	ImageSymClassTypeDefinition = 13

	// ImageSymClassUndefinedStatic indicates a static data declaration.
	ImageSymClassUndefinedStatic = 14

	// ImageSymClassEnumTag indicates an enumerated type tagname entry.
	ImageSymClassEnumTag = 15

	// ImageSymClassMemberOfEnum indicates a member of an enumeration. The
	// Value field specifies the n th member.
	ImageSymClassMemberOfEnum = 16

	// ImageSymClassRegisterParam indicates a register parameter.
	ImageSymClassRegisterParam = 17

	// ImageSymClassBitField indicates a bit-field reference. The Value field
	// specifies the n th bit in the bit field.
	ImageSymClassBitField = 18

	// ImageSymClassBlock indicates a .bb (beginning of block) or .eb (end of
	// block) record. The Value field is the relocatable address of the code
	// location.
	ImageSymClassBlock = 100

	// ImageSymClassFunction indicates a value that Microsoft tools use for
	// symbol records that define the extent of a function: begin function (.bf
	// ), end function ( .ef ), and lines in function ( .lf ). For .lf
	// records, the Value field gives the number of source lines in the
	// function. For .ef records, the Value field gives the size of the
	// function code.
	ImageSymClassFunction = 101

	// ImageSymClassEndOfStruct indicates an end-of-structure entry.
	ImageSymClassEndOfStruct = 102

	// ImageSymClassFile indicates a value that Microsoft tools, as well as
	// traditional COFF format, use for the source-file symbol record. The
	// symbol is followed by auxiliary records that name the file.
	ImageSymClassFile = 103

	// ImageSymClassSsection indicates a definition of a section (Microsoft
	// tools use STATIC storage class instead).
	ImageSymClassSsection = 104

	// ImageSymClassWeakExternal indicates a weak external. For more
	// information, see Auxiliary Format 3: Weak Externals.
	ImageSymClassWeakExternal = 24

	// ImageSymClassClrToken indicates a CLR token symbol. The name is an ASCII
	// string that consists of the hexadecimal value of the token. For more
	// information, see CLR Token Definition (Object Only).
	ImageSymClassClrToken = 25

	//
	// Section Number Values.
	//

	// ImageSymUndefined indicates that the symbol record is not yet assigned a
	// section. A value of zero indicates that a reference to an external
	// symbol is defined elsewhere. A value of non-zero is a common symbol with
	// a size that is specified by the value.
	ImageSymUndefined = 0

	// ImageSymAbsolute indicates that the symbol has an absolute
	// (non-relocatable) value and is not an address.
	ImageSymAbsolute = -1

	// ImageSymDebug indicates that the symbol provides general type or
	// debugging information but does not correspond to a section. Microsoft
	// tools use this setting along with .file records (storage class FILE).
	ImageSymDebug = -2
)

var (
	errCOFFTableNotPresent = errors.New(
		"PE image does not contains a COFF symbol table")
	errNoCOFFStringInTable = errors.New(
		"PE image got a PointerToSymbolTable but no string in the COFF string table")
	errCOFFSymbolOutOfBounds = errors.New(
		"COFF symbol offset out of bounds")
	errCOFFSymbolsTooHigh = errors.New(
		"COFF symbols count is absurdly high")
)

// COFFSymbol represents an entry in the COFF symbol table, which it is an
// array of records, each 18 bytes long. Each record is either a standard or
// auxiliary symbol-table record. A standard record defines a symbol or name
// and has the following format.
type COFFSymbol struct {
	// The name of the symbol, represented by a union of three structures. An
	// array of 8 bytes is used if the name is not more than 8 bytes long.
	// union {
	//    BYTE     ShortName[8];
	//    struct {
	//        DWORD   Short;     // if 0, use LongName
	//        DWORD   Long;      // offset into string table
	//    } Name;
	//    DWORD   LongName[2];    // PBYTE  [2]
	// } N;
	Name [8]byte `json:"name"`

	// The value that is associated with the symbol. The interpretation of this
	// field depends on SectionNumber and StorageClass. A typical meaning is
	// the relocatable address.
	Value uint32 `json:"value"`

	// The signed integer that identifies the section, using a one-based index
	// into the section table. Some values have special meaning.
	// See "Section Number Values."
	SectionNumber int16 `json:"section_number"`

	// A number that represents type. Microsoft tools set this field to
	// 0x20 (function) or 0x0 (not a function). For more information,
	// see Type Representation.
	Type uint16 `json:"type"`

	// An enumerated value that represents storage class.
	// For more information, see Storage Class.
	StorageClass uint8 `json:"storage_class"`

	// The number of auxiliary symbol table entries that follow this record.
	NumberOfAuxSymbols uint8 `json:"number_of_aux_symbols"`
}

// COFF holds properties related to the COFF format.
type COFF struct {
	SymbolTable       []COFFSymbol `json:"symbol_table"`
	StringTable       []string     `json:"string_table"`
	StringTableOffset uint32       `json:"string_table_offset"`
	// Map the symbol offset => symbol name.
	StringTableM map[uint32]string `json:"-"`
}

// ParseCOFFSymbolTable parses the COFF symbol table. The symbol table is
// inherited from the traditional COFF format. It is distinct from Microsoft
// Visual C++ debug information. A file can contain both a COFF symbol table
// and Visual C++ debug information, and the two are kept separate. Some
// Microsoft tools use the symbol table for limited but important purposes,
// such as communicating COMDAT information to the linker. Section names and
// file names, as well as code and data symbols, are listed in the symbol table.
func (pe *File) ParseCOFFSymbolTable() error {
	pointerToSymbolTable := pe.NtHeader.FileHeader.PointerToSymbolTable
	if pointerToSymbolTable == 0 {
		return errCOFFTableNotPresent
	}

	symCount := pe.NtHeader.FileHeader.NumberOfSymbols
	if symCount == 0 {
		return nil
	}
	if symCount > pe.opts.MaxCOFFSymbolsCount {
		pe.addAnomaly(AnoCOFFSymbolsCount)
		return errCOFFSymbolsTooHigh
	}

	// The location of the symbol table is indicated in the COFF header.
	offset := pe.NtHeader.FileHeader.PointerToSymbolTable

	// The symbol table is an array of records, each 18 bytes long.
	size := uint32(binary.Size(COFFSymbol{}))
	symbols := make([]COFFSymbol, symCount)

	// Each record is either a standard or auxiliary symbol-table record.
	// A standard record defines a symbol or name and has the COFFSymbol STRUCT format.
	for i := uint32(0); i < symCount; i++ {
		err := pe.structUnpack(&symbols[i], offset, size)
		if err != nil {
			return err
		}
		offset += size
	}

	pe.COFF.SymbolTable = symbols

	// Get the COFF string table.
	pe.COFFStringTable()

	pe.HasCOFF = true
	return nil
}

// COFFStringTable retrieves the list of strings in the COFF string table if
// any.
func (pe *File) COFFStringTable() error {
	m := make(map[uint32]string)
	pointerToSymbolTable := pe.NtHeader.FileHeader.PointerToSymbolTable
	if pointerToSymbolTable == 0 {
		return errCOFFTableNotPresent
	}

	symCount := pe.NtHeader.FileHeader.NumberOfSymbols
	if symCount == 0 {
		return nil
	}
	if symCount > pe.opts.MaxCOFFSymbolsCount {
		pe.addAnomaly(AnoCOFFSymbolsCount)
		return errCOFFSymbolsTooHigh
	}

	// COFF String Table immediately following the COFF symbol table. The
	// position of this table is found by taking the symbol table address in
	// the COFF header and adding the number of symbols multiplied by the size
	// of a symbol.
	size := uint32(binary.Size(COFFSymbol{}))
	offset := pointerToSymbolTable + (size * symCount)

	// At the beginning of the COFF string table are 4 bytes that contain the
	// total size (in bytes) of the rest of the string table. This size
	// includes the size field itself, so that the value in this location would
	// be 4 if no strings were present.
	pe.COFF.StringTableOffset = offset
	strTableSize, err := pe.ReadUint32(offset)
	if err != nil {
		return err
	}
	if strTableSize <= 4 {
		return errNoCOFFStringInTable
	}
	offset += 4

	// Following the size are null-terminated strings that are pointed to by
	// symbols in the COFF symbol table. We create a map to map offset to
	// string.
	end := offset + strTableSize - 4
	for offset < end {
		len, str := pe.readASCIIStringAtOffset(offset, MaxCOFFSymStrLength)
		if len == 0 {
			break
		}
		m[offset] = str
		offset += len + 1
		pe.COFF.StringTable = append(pe.COFF.StringTable, str)
	}

	pe.COFF.StringTableM = m
	return nil
}

// String returns the representation of the symbol name.
func (symbol *COFFSymbol) String(pe *File) (string, error) {
	var short, long uint32

	// The ShortName field in a symbol table consists of 8 bytes
	// that contain the name itself, if it is not more than 8
	// bytes long, or the ShortName field gives an offset into
	// the string table.
	highDw := bytes.NewBuffer(symbol.Name[4:])
	lowDw := bytes.NewBuffer(symbol.Name[:4])
	errl := binary.Read(lowDw, binary.LittleEndian, &short)
	errh := binary.Read(highDw, binary.LittleEndian, &long)
	if errl != nil || errh != nil {
		return "", errCOFFSymbolOutOfBounds
	}

	// To determine whether the name itself or an offset is given,
	// test the first 4 bytes for equality to zero.
	if short != 0 {
		name := strings.Replace(string(symbol.Name[:]), "\x00", "", -1)
		return name, nil
	}

	// Long name offset to the string table.
	strOff := pe.COFF.StringTableOffset + long
	name := pe.COFF.StringTableM[strOff]
	return name, nil
}

// SectionNumberName returns the name of the section corresponding to a section
// symbol number if any.
func (symbol *COFFSymbol) SectionNumberName(pe *File) string {

	// Normally, the Section Value field in a symbol table entry is a one-based
	// index into the section table. However, this field is a signed integer
	// and can take negative values. The following values, less than one, have
	// special meanings.
	if symbol.SectionNumber > 0 && symbol.SectionNumber < int16(len(pe.Sections)) {
		return pe.Sections[symbol.SectionNumber-1].String()
	}

	switch symbol.SectionNumber {
	case ImageSymUndefined:
		return "Undefined"
	case ImageSymAbsolute:
		return "Absolute"
	case ImageSymDebug:
		return "Debug"
	}

	return "?"
}

// PrettyCOFFTypeRepresentation returns the string representation of the `Type`
// field of a COFF table entry.
func (pe *File) PrettyCOFFTypeRepresentation(k uint16) string {
	coffSymTypeMap := map[uint16]string{
		ImageSymTypeNull:   "Null",
		ImageSymTypeVoid:   "Void",
		ImageSymTypeChar:   "Char",
		ImageSymTypeShort:  "Short",
		ImageSymTypeInt:    "Int",
		ImageSymTypeLong:   "Long",
		ImageSymTypeFloat:  "Float",
		ImageSymTypeDouble: "Double",
		ImageSymTypeStruct: "Struct",
		ImageSymTypeUnion:  "Union",
		ImageSymTypeEnum:   "Enum",
		ImageSymTypeMoe:    "Moe",
		ImageSymTypeByte:   "Byte",
		ImageSymTypeWord:   "Word",
		ImageSymTypeUint:   "Uint",
		ImageSymTypeDword:  "Dword",
	}

	if value, ok := coffSymTypeMap[k]; ok {
		return value
	}
	return ""
}

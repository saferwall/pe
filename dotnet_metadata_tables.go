// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

// the struct definition and comments are from the ECMA-335 spec 6th edition
// https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf

// Module 0x00
type ModuleTableRow struct {
	// a 2-byte value, reserved, shall be zero
	Generation uint16 `json:"generation"`
	// an index into the String heap
	Name uint32 `json:"name"`
	// an index into the Guid heap; simply a Guid used to distinguish between
	// two versions of the same module
	Mvid uint32 `json:"mvid"`
	// an index into the Guid heap; reserved, shall be zero
	EncID uint32 `json:"enc_id"`
	// an index into the Guid heap; reserved, shall be zero
	EncBaseID uint32 `json:"enc_base_id"`
}

// Module 0x00
func (pe *File) parseMetadataModuleTable(off uint32) ([]ModuleTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Module].CountCols)
	rows := make([]ModuleTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Generation, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxGUID, off, &rows[i].Mvid); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxGUID, off, &rows[i].EncID); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxGUID, off, &rows[i].EncBaseID); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// TypeRef 0x01
type TypeRefTableRow struct {
	// an index into a Module, ModuleRef, AssemblyRef or TypeRef table, or null;
	// more precisely, a ResolutionScope (§II.24.2.6) coded index.
	ResolutionScope uint32 `json:"resolution_scope"`
	// an index into the String heap
	TypeName uint32 `json:"type_name"`
	// an index into the String heap
	TypeNamespace uint32 `json:"type_namespace"`
}

// TypeRef 0x01
func (pe *File) parseMetadataTypeRefTable(off uint32) ([]TypeRefTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[TypeRef].CountCols)
	rows := make([]TypeRefTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxResolutionScope, off, &rows[i].ResolutionScope); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].TypeName); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].TypeNamespace); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// TypeDef 0x02
type TypeDefTableRow struct {
	// a 4-byte bitmask of type TypeAttributes, §II.23.1.15
	Flags uint32 `json:"flags"`
	// an index into the String heap
	TypeName uint32 `json:"type_name"`
	// an index into the String heap
	TypeNamespace uint32 `json:"type_namespace"`
	// an index into the TypeDef, TypeRef, or TypeSpec table; more precisely,
	// a TypeDefOrRef (§II.24.2.6) coded index
	Extends uint32 `json:"extends"`
	// an index into the Field table; it marks the first of a contiguous run
	// of Fields owned by this Type
	FieldList uint32 `json:"field_list"`
	// an index into the MethodDef table; it marks the first of a contiguous
	// run of Methods owned by this Type
	MethodList uint32 `json:"method_list"`
}

// TypeDef 0x02
func (pe *File) parseMetadataTypeDefTable(off uint32) ([]TypeDefTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[TypeDef].CountCols)
	rows := make([]TypeDefTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Flags, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].TypeName); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].TypeNamespace); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxTypeDefOrRef, off, &rows[i].Extends); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxField, off, &rows[i].FieldList); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxMethodDef, off, &rows[i].MethodList); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// Field 0x04
type FieldTableRow struct {
	// a 2-byte bitmask of type FieldAttributes, §II.23.1.5
	Flags uint16 `json:"flags"`
	// an index into the String heap
	Name uint32 `json:"name"`
	// an index into the Blob heap
	Signature uint32 `json:"signature"`
}

// Field 0x04
func (pe *File) parseMetadataFieldTable(off uint32) ([]FieldTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Field].CountCols)
	rows := make([]FieldTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Flags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Signature); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// MethodDef 0x06
type MethodDefTableRow struct {
	// a 4-byte constant
	RVA uint32 `json:"rva"`
	// a 2-byte bitmask of type MethodImplAttributes, §II.23.1.10
	ImplFlags uint16 `json:"impl_flags"`
	// a 2-byte bitmask of type MethodAttributes, §II.23.1.10
	Flags uint16 `json:"flags"`
	// an index into the String heap
	Name uint32 `json:"name"`
	// an index into the Blob heap
	Signature uint32 `json:"signature"`
	// an index into the Param table
	ParamList uint32 `json:"param_list"`
}

// MethodDef 0x06
func (pe *File) parseMetadataMethodDefTable(off uint32) ([]MethodDefTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[MethodDef].CountCols)
	rows := make([]MethodDefTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].RVA, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if rows[i].ImplFlags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].Flags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Signature); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxParam, off, &rows[i].ParamList); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// Param 0x08
type ParamTableRow struct {
	// a 2-byte bitmask of type ParamAttributes, §II.23.1.13
	Flags uint16 `json:"flags"`
	// a 2-byte constant
	Sequence uint16 `json:"sequence"`
	// an index into the String heap
	Name uint32 `json:"name"`
}

// Param 0x08
func (pe *File) parseMetadataParamTable(off uint32) ([]ParamTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Param].CountCols)
	rows := make([]ParamTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Flags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].Sequence, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// InterfaceImpl 0x09
type InterfaceImplTableRow struct {
	// an index into the TypeDef table
	Class uint32 `json:"class"`
	// an index into the TypeDef, TypeRef, or TypeSpec table; more precisely,
	// a TypeDefOrRef (§II.24.2.6) coded index
	Interface uint32 `json:"interface"`
}

// InterfaceImpl 0x09
func (pe *File) parseMetadataInterfaceImplTable(off uint32) ([]InterfaceImplTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[InterfaceImpl].CountCols)
	rows := make([]InterfaceImplTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].Class); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxTypeDefOrRef, off, &rows[i].Interface); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// MembersRef 0x0a
type MemberRefTableRow struct {
	// an index into the MethodDef, ModuleRef,TypeDef, TypeRef, or TypeSpec
	// tables; more precisely, a MemberRefParent (§II.24.2.6) coded index
	Class uint32 `json:"class"`
	// // an index into the String heap
	Name uint32 `json:"name"`
	// an index into the Blob heap
	Signature uint32 `json:"signature"`
}

// MembersRef 0x0a
func (pe *File) parseMetadataMemberRefTable(off uint32) ([]MemberRefTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[MemberRef].CountCols)
	rows := make([]MemberRefTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxMemberRefParent, off, &rows[i].Class); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Signature); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

	}
	return rows, n, nil
}

// Constant 0x0b
type ConstantTableRow struct {
	// a 1-byte constant, followed by a 1-byte padding zero
	Type uint8 `json:"type"`
	// padding zero
	Padding uint8 `json:"padding"`
	// padding zero
	// an index into the Param, Field, or Property table; more precisely,
	// a HasConstant (§II.24.2.6) coded index
	Parent uint32 `json:"parent"`
	// an index into the Blob heap
	Value uint32 `json:"value"`
}

// Constant 0x0b
func (pe *File) parseMetadataConstantTable(off uint32) ([]ConstantTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Constant].CountCols)
	rows := make([]ConstantTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Type, err = pe.ReadUint8(off); err != nil {
			return rows, n, err
		}
		off += 1
		n += 1

		if rows[i].Padding, err = pe.ReadUint8(off); err != nil {
			return rows, n, err
		}
		off += 1
		n += 1

		if indexSize, err = pe.readFromMetadataStream(idxHasConstant, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Value); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// CustomAttribute 0x0c
type CustomAttributeTableRow struct {
	// an index into a metadata table that has an associated HasCustomAttribute
	// (§II.24.2.6) coded index
	Parent uint32 `json:"parent"`
	// an index into the MethodDef or MemberRef table; more precisely,
	// a CustomAttributeType (§II.24.2.6) coded index
	Type uint32 `json:"type"`
	// an index into the Blob heap
	Value uint32 `json:"value"`
}

// CustomAttribute 0x0c
func (pe *File) parseMetadataCustomAttributeTable(off uint32) ([]CustomAttributeTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[CustomAttribute].CountCols)
	rows := make([]CustomAttributeTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxHasCustomAttributes, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxCustomAttributeType, off, &rows[i].Type); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Value); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// FieldMarshal 0x0d
type FieldMarshalTableRow struct {
	// an index into Field or Param table; more precisely,
	// a HasFieldMarshal (§II.24.2.6) coded index
	Parent uint32 `json:"parent"`
	// an index into the Blob heap
	NativeType uint32 `json:"native_type"`
}

// FieldMarshal 0x0d
func (pe *File) parseMetadataFieldMarshalTable(off uint32) ([]FieldMarshalTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[FieldMarshal].CountCols)
	rows := make([]FieldMarshalTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxHasFieldMarshall, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].NativeType); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// DeclSecurity 0x0e
type DeclSecurityTableRow struct {
	// a 2-byte value
	Action uint16 `json:"action"`
	// an index into the TypeDef, MethodDef, or Assembly table;
	// more precisely, a HasDeclSecurity (§II.24.2.6) coded index
	Parent uint32 `json:"parent"`
	// // an index into the Blob heap
	PermissionSet uint32 `json:"permission_set"`
}

// DeclSecurity 0x0e
func (pe *File) parseMetadataDeclSecurityTable(off uint32) ([]DeclSecurityTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[DeclSecurity].CountCols)
	rows := make([]DeclSecurityTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Action, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxHasDeclSecurity, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].PermissionSet); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// ClassLayout 0x0f
type ClassLayoutTableRow struct {
	// a 2-byte constant
	PackingSize uint16 `json:"packing_size"`
	// a 4-byte constant
	ClassSize uint32 `json:"class_size"`
	// an index into the TypeDef table
	Parent uint32 `json:"parent"`
}

// ClassLayout 0x0f
func (pe *File) parseMetadataClassLayoutTable(off uint32) ([]ClassLayoutTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[ClassLayout].CountCols)
	rows := make([]ClassLayoutTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].PackingSize, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].ClassSize, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// FieldLayout 0x10
type FieldLayoutTableRow struct {
	Offset uint32 `json:"offset"` // a 4-byte constant
	Field  uint32 `json:"field"`  // an index into the Field table
}

// FieldLayout 0x10
func (pe *File) parseMetadataFieldLayoutTable(off uint32) ([]FieldLayoutTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[FieldLayout].CountCols)
	rows := make([]FieldLayoutTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Offset, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxField, off, &rows[i].Field); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// StandAloneSig 0x11
type StandAloneSigTableRow struct {
	Signature uint32 `json:"signature"` // an index into the Blob heap
}

// StandAloneSig 0x11
func (pe *File) parseMetadataStandAloneSignTable(off uint32) ([]StandAloneSigTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[StandAloneSig].CountCols)
	rows := make([]StandAloneSigTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Signature); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// EventMap 0x12
type EventMapTableRow struct {
	// an index into the TypeDef table
	Parent uint32 `json:"parent"`
	// an index into the Event table
	EventList uint32 `json:"event_list"`
}

// EventMap 0x12
func (pe *File) parseMetadataEventMapTable(off uint32) ([]EventMapTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[EventMap].CountCols)
	rows := make([]EventMapTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxEvent, off, &rows[i].EventList); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

	}
	return rows, n, nil
}

// Event 0x14
type EventTableRow struct {
	// a 2-byte bitmask of type EventAttributes, §II.23.1.4
	EventFlags uint16 `json:"event_flags"`
	// an index into the String heap
	Name uint32 `json:"name"`
	// an index into a TypeDef, a TypeRef, or TypeSpec table; more precisely,
	// a TypeDefOrRef (§II.24.2.6) coded index)
	EventType uint32 `json:"event_type"`
}

// Event 0x14
func (pe *File) parseMetadataEventTable(off uint32) ([]EventTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Event].CountCols)
	rows := make([]EventTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].EventFlags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxTypeDefOrRef, off, &rows[i].EventType); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// PropertyMap 0x15
type PropertyMapTableRow struct {
	// an index	into the TypeDef table
	Parent uint32 `json:"parent"`
	// an index into the Property table
	PropertyList uint32 `json:"property_list"`
}

// PropertyMap 0x15
func (pe *File) parseMetadataPropertyMapTable(off uint32) ([]PropertyMapTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[PropertyMap].CountCols)
	rows := make([]PropertyMapTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].Parent); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxProperty, off, &rows[i].PropertyList); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// Property 0x17
type PropertyTableRow struct {
	// a 2-byte bitmask of type PropertyAttributes, §II.23.1.14
	Flags uint16 `json:"flags"`
	// an index into the String heap
	Name uint32 `json:"name"`
	// an index into the Blob heap
	Type uint32 `json:"type"`
}

// Property 0x17
func (pe *File) parseMetadataPropertyTable(off uint32) ([]PropertyTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Property].CountCols)
	rows := make([]PropertyTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Flags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Type); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// MethodSemantics 0x18
type MethodSemanticsTableRow struct {
	// a 2-byte bitmask of type MethodSemanticsAttributes, §II.23.1.12
	Semantics uint16 `json:"semantics"`
	// an index into the MethodDef table
	Method uint32 `json:"method"`
	// an index into the Event or Property table; more precisely,
	// a HasSemantics (§II.24.2.6) coded index
	Association uint32 `json:"association"`
}

// MethodSemantics 0x18
func (pe *File) parseMetadataMethodSemanticsTable(off uint32) ([]MethodSemanticsTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[MethodSemantics].CountCols)
	rows := make([]MethodSemanticsTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Semantics, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxMethodDef, off, &rows[i].Method); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxHasSemantics, off, &rows[i].Association); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// MethodImpl 0x19
type MethodImplTableRow struct {
	// an index into the TypeDef table
	Class uint32 `json:"class"`
	// an index into the MethodDef or MemberRef table; more precisely, a
	// MethodDefOrRef (§II.24.2.6) coded index
	MethodBody uint32 `json:"method_body"`
	// // an index into the MethodDef or MemberRef table; more precisely, a
	// MethodDefOrRef (§II.24.2.6) coded index
	MethodDeclaration uint32 `json:"method_declaration"`
}

// MethodImpl 0x19
func (pe *File) parseMetadataMethodImplTable(off uint32) ([]MethodImplTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[MethodImpl].CountCols)
	rows := make([]MethodImplTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].Class); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxMethodDefOrRef, off, &rows[i].MethodBody); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxMethodDefOrRef, off, &rows[i].MethodDeclaration); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// ModuleRef 0x1a
type ModuleRefTableRow struct {
	// an index into the String heap
	Name uint32 `json:"name"`
}

// ModuleRef 0x1a
func (pe *File) parseMetadataModuleRefTable(off uint32) ([]ModuleRefTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[ModuleRef].CountCols)
	rows := make([]ModuleRefTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// TypeSpec 0x1b
type TypeSpecTableRow struct {
	// an index into the Blob heap
	Signature uint32 `json:"signature"`
}

// TypeSpec 0x1b
func (pe *File) parseMetadataTypeSpecTable(off uint32) ([]TypeSpecTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[TypeSpec].CountCols)
	rows := make([]TypeSpecTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Signature); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// ImplMap 0x1c
type ImplMapTableRow struct {
	// a 2-byte bitmask of type PInvokeAttributes, §23.1.8
	MappingFlags uint16 `json:"mapping_flags"`
	// an index into the Field or MethodDef table; more precisely,
	// a MemberForwarded (§II.24.2.6) coded index)
	MemberForwarded uint32 `json:"member_forwarded"`
	// an index into the String heap
	ImportName uint32 `json:"import_name"`
	// an index into the ModuleRef table
	ImportScope uint32 `json:"import_scope"`
}

// ImplMap 0x1c
func (pe *File) parseMetadataImplMapTable(off uint32) ([]ImplMapTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[ImplMap].CountCols)
	rows := make([]ImplMapTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].MappingFlags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxMemberForwarded, off, &rows[i].MemberForwarded); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].ImportName); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxModuleRef, off, &rows[i].ImportScope); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// FieldRVA 0x1d
type FieldRVATableRow struct {
	// 4-byte constant
	RVA uint32 `json:"rva"`
	// an index into Field table
	Field uint32 `json:"field"`
}

// FieldRVA 0x1d
func (pe *File) parseMetadataFieldRVATable(off uint32) ([]FieldRVATableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[FieldRVA].CountCols)
	rows := make([]FieldRVATableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].RVA, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxField, off, &rows[i].Field); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// Assembly 0x20
type AssemblyTableRow struct {
	// a 4-byte constant of type AssemblyHashAlgorithm, §II.23.1.1
	HashAlgId uint32 `json:"hash_alg_id"`
	// a 2-byte constant
	MajorVersion uint16 `json:"major_version"`
	// a 2-byte constant
	MinorVersion uint16 `json:"minor_version"`
	// a 2-byte constant
	BuildNumber uint16 `json:"build_number"`
	// a 2-byte constant
	RevisionNumber uint16 `json:"revision_number"`
	// a 4-byte bitmask of type AssemblyFlags, §II.23.1.2
	Flags uint32 `json:"flags"`
	// an index into the Blob heap
	PublicKey uint32 `json:"public_key"`
	// an index into the String heap
	Name uint32 `json:"name"`
	// an index into the String heap
	Culture uint32 `json:"culture"`
}

// Assembly 0x20
func (pe *File) parseMetadataAssemblyTable(off uint32) ([]AssemblyTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[Assembly].CountCols)
	rows := make([]AssemblyTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].HashAlgId, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if rows[i].MajorVersion, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].MinorVersion, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].BuildNumber, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].RevisionNumber, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].Flags, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].PublicKey); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Culture); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// AssemblyProcessor 0x21
type AssemblyProcessorTableRow struct {
	Processor uint32 `json:"processor"` // a 4-byte constant
}

// AssemblyOS 0x22
type AssemblyOSTableRow struct {
	OSPlatformID   uint32 `json:"os_platform_id"`   // a 4-byte constant
	OSMajorVersion uint32 `json:"os_major_version"` // a 4-byte constant
	OSMinorVersion uint32 `json:"os_minor_version"` // a 4-byte constant
}

// AssemblyRef 0x23
type AssemblyRefTableRow struct {
	MajorVersion     uint16 `json:"major_version"`       // a 2-byte constant
	MinorVersion     uint16 `json:"minor_version"`       // a 2-byte constant
	BuildNumber      uint16 `json:"build_number"`        // a 2-byte constant
	RevisionNumber   uint16 `json:"revision_number"`     // a 2-byte constant
	Flags            uint32 `json:"flags"`               // a 4-byte bitmask of type AssemblyFlags, §II.23.1.2
	PublicKeyOrToken uint32 `json:"public_key_or_token"` // an index into the Blob heap, indicating the public key or token that identifies the author of this Assembly
	Name             uint32 `json:"name"`                // an index into the String heap
	Culture          uint32 `json:"culture"`             // an index into the String heap
	HashValue        uint32 `json:"hash_value"`          // an index into the Blob heap
}

// AssemblyRef 0x23
func (pe *File) parseMetadataAssemblyRefTable(off uint32) ([]AssemblyRefTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[AssemblyRef].CountCols)
	rows := make([]AssemblyRefTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].MajorVersion, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].MinorVersion, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].BuildNumber, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].RevisionNumber, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if rows[i].Flags, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].PublicKeyOrToken); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Culture); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].HashValue); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// AssemblyRefProcessor 0x24
type AssemblyRefProcessorTableRow struct {
	Processor   uint32 `json:"processor"`    // a 4-byte constant
	AssemblyRef uint32 `json:"assembly_ref"` // an index into the AssemblyRef table
}

// AssemblyRefOS 0x25
type AssemblyRefOSTableRow struct {
	OSPlatformID   uint32 `json:"os_platform_id"`   // a 4-byte constant
	OSMajorVersion uint32 `json:"os_major_version"` // a 4-byte constant
	OSMinorVersion uint32 `json:"os_minor_version"` // a 4-byte constan)
	AssemblyRef    uint32 `json:"assembly_ref"`     // an index into the AssemblyRef table
}

// File 0x26
type FileTableRow struct {
	Flags     uint32 `json:"flags"`      // a 4-byte bitmask of type FileAttributes, §II.23.1.6
	Name      uint32 `json:"name"`       // an index into the String heap
	HashValue uint32 `json:"hash_value"` // an index into the Blob heap
}

// ExportedType 0x27
type ExportedTypeTableRow struct {
	Flags          uint32 `json:"flags"`          // a 4-byte bitmask of type TypeAttributes, §II.23.1.15
	TypeDefId      uint32 `json:"type_def_id"`    // a 4-byte index into a TypeDef table of another module in this Assembly
	TypeName       uint32 `json:"type_name"`      // an index into the String heap
	TypeNamespace  uint32 `json:"type_namespace"` // an index into the String heap
	Implementation uint32 `json:"implementation"` // an index (more precisely, an Implementation (§II.24.2.6) coded index
}

// ExportedType 0x27
func (pe *File) parseMetadataExportedTypeTable(off uint32) ([]ExportedTypeTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[ExportedType].CountCols)
	rows := make([]ExportedTypeTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Flags, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if rows[i].TypeDefId, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].TypeName); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].TypeNamespace); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxImplementation, off, &rows[i].Implementation); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// ManifestResource 0x28
type ManifestResourceTableRow struct {
	Offset         uint32 `json:"offset"`         // a 4-byte constant
	Flags          uint32 `json:"flags"`          // a 4-byte bitmask of type ManifestResourceAttributes, §II.23.1.9
	Name           uint32 `json:"name"`           // an index into the String heap
	Implementation uint32 `json:"implementation"` // an index into a File table, a AssemblyRef table, or null; more precisely, an Implementation (§II.24.2.6) coded index
}

// ManifestResource 0x28
func (pe *File) parseMetadataManifestResourceTable(off uint32) ([]ManifestResourceTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[ManifestResource].CountCols)
	rows := make([]ManifestResourceTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Offset, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if rows[i].Flags, err = pe.ReadUint32(off); err != nil {
			return rows, n, err
		}
		off += 4
		n += 4

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxImplementation, off, &rows[i].Implementation); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// NestedClass 0x29
type NestedClassTableRow struct {
	NestedClass    uint32 `json:"nested_class"`    // an index into the TypeDef table
	EnclosingClass uint32 `json:"enclosing_class"` // an index into the TypeDef table
}

// NestedClass 0x29
func (pe *File) parseMetadataNestedClassTable(off uint32) ([]NestedClassTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[NestedClass].CountCols)
	rows := make([]NestedClassTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].NestedClass); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxTypeDef, off, &rows[i].EnclosingClass); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// GenericParam 0x2a
type GenericParamTableRow struct {
	Number uint16 `json:"number"` // the 2-byte index of the generic parameter, numbered left-to-right, from zero
	Flags  uint16 `json:"flags"`  // a 2-byte bitmask of type GenericParamAttributes, §II.23.1.7
	Owner  uint32 `json:"owner"`  // an index into the TypeDef or MethodDef table, specifying the Type or Method to which this generic parameter applies; more precisely, a TypeOrMethodDef (§II.24.2.6) coded index
	Name   uint32 `json:"name"`   // a non-null index into the String heap, giving the name for the generic parameter
}

// GenericParam 0x2a
func (pe *File) parseMetadataGenericParamTable(off uint32) ([]GenericParamTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[GenericParam].CountCols)
	rows := make([]GenericParamTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if rows[i].Number, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2
		if rows[i].Flags, err = pe.ReadUint16(off); err != nil {
			return rows, n, err
		}
		off += 2
		n += 2

		if indexSize, err = pe.readFromMetadataStream(idxTypeOrMethodDef, off, &rows[i].Owner); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxString, off, &rows[i].Name); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// MethodSpec 0x2b
type MethodSpecTableRow struct {
	Method        uint32 `json:"method"`        // an index into the MethodDef or MemberRef table, specifying to which generic method this row refers; that is, which generic method this row is an instantiation of; more precisely, a MethodDefOrRef (§II.24.2.6) coded index
	Instantiation uint32 `json:"instantiation"` // an index into the Blob heap
}

// MethodSpec 0x2b
func (pe *File) parseMetadataMethodSpecTable(off uint32) ([]MethodSpecTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[MethodSpec].CountCols)
	rows := make([]MethodSpecTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxMethodDefOrRef, off, &rows[i].Method); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxBlob, off, &rows[i].Instantiation); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// GenericParamConstraint 0x2c
type GenericParamConstraintTableRow struct {
	Owner      uint32 `json:"owner"`      // an index into the GenericParam table, specifying to which generic parameter this row refers
	Constraint uint32 `json:"constraint"` // an index into the TypeDef, TypeRef, or TypeSpec tables, specifying from which class this generic parameter is constrained to derive; or which interface this generic parameter is constrained to implement; more precisely, a TypeDefOrRef (§II.24.2.6) coded index
}

// GenericParamConstraint 0x2c
func (pe *File) parseMetadataGenericParamConstraintTable(off uint32) ([]GenericParamConstraintTableRow, uint32, error) {
	var err error
	var indexSize uint32
	var n uint32

	rowCount := int(pe.CLR.MetadataTables[GenericParamConstraint].CountCols)
	rows := make([]GenericParamConstraintTableRow, rowCount)
	for i := 0; i < rowCount; i++ {
		if indexSize, err = pe.readFromMetadataStream(idxGenericParam, off, &rows[i].Owner); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize

		if indexSize, err = pe.readFromMetadataStream(idxTypeDefOrRef, off, &rows[i].Constraint); err != nil {
			return rows, n, err
		}
		off += indexSize
		n += indexSize
	}
	return rows, n, nil
}

// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"sort"
	"strconv"
	"testing"
)

func TestClrDirectoryHeaders(t *testing.T) {

	type TestClrHeaders struct {
		clrHeader            ImageCOR20Header
		mdHeader             MetadataHeader
		mdStreamHeaders      []MetadataStreamHeader
		mdTablesStreamHeader MetadataTableStreamHeader
	}

	tests := []struct {
		in  string
		out TestClrHeaders
	}{
		{
			getAbsoluteFilePath("test/mscorlib.dll"),
			TestClrHeaders{
				clrHeader: ImageCOR20Header{
					Cb:                  0x48,
					MajorRuntimeVersion: 0x2,
					MinorRuntimeVersion: 0x5,
					MetaData: ImageDataDirectory{
						VirtualAddress: 0x2050,
						Size:           0xae34,
					},
					Flags:                0x9,
					EntryPointRVAorToken: 0x0,
					StrongNameSignature: ImageDataDirectory{
						VirtualAddress: 0xce84,
						Size:           0x80,
					},
				},
				mdHeader: MetadataHeader{
					Signature:     0x424a5342,
					MajorVersion:  0x1,
					MinorVersion:  0x1,
					ExtraData:     0x0,
					VersionString: 0xc,
					Version:       "v4.0.30319",
					Flags:         0x0,
					Streams:       0x5,
				},
				mdStreamHeaders: []MetadataStreamHeader{
					{
						Offset: 0x6c,
						Size:   0x4c38,
						Name:   "#~",
					},
					{
						Offset: 0x4ca4,
						Size:   0x5ed4,
						Name:   "#Strings",
					},
					{
						Offset: 0xab78,
						Size:   0x4,
						Name:   "#US",
					},
					{
						Offset: 0xab7c,
						Size:   0x10,
						Name:   "#GUID",
					},
					{
						Offset: 0xab8c,
						Size:   0x2a8,
						Name:   "#Blob",
					},
				},
				mdTablesStreamHeader: MetadataTableStreamHeader{
					Reserved:     0x0,
					MajorVersion: 0x2,
					MinorVersion: 0x0,
					Heaps:        0x0,
					RID:          0x1,
					MaskValid:    0x8900005407,
					Sorted:       0x16003301fa00,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			var va, size uint32
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseCLRHeaderDirectory(va, size)
			if err != nil {
				t.Fatalf("parseCLRHeaderDirectory(%s) failed, reason: %v", tt.in, err)
			}
			clr := file.CLR
			if clr.CLRHeader != tt.out.clrHeader {
				t.Errorf("CLR header assertion failed, got %v, want %v",
					clr.CLRHeader, tt.out.clrHeader)
			}

			if clr.MetadataHeader != tt.out.mdHeader {
				t.Errorf("CLR metadata header assertion failed, got %v, want %v",
					clr.MetadataHeader, tt.out.mdHeader)
			}

			if !reflect.DeepEqual(clr.MetadataStreamHeaders, tt.out.mdStreamHeaders) {
				t.Errorf("CLR metadata stream headers assertion failed, got %v, want %v",
					clr.MetadataStreamHeaders, tt.out.mdStreamHeaders)
			}
		})
	}
}

func TestClrDirectoryMetadataTables(t *testing.T) {

	type TestClrMetadataTable struct {
		tableKind int
		table     MetadataTable
	}

	tests := []struct {
		in  string
		out []TestClrMetadataTable
	}{
		{
			getAbsoluteFilePath("test/mscorlib.dll"),
			[]TestClrMetadataTable{
				{
					tableKind: Module,
					table: MetadataTable{
						Name:      "Module",
						CountCols: 0x1,
						Content: []ModuleTableRow{
							{
								Generation: 0x0,
								Name:       0x2cd7,
								Mvid:       0x1,
								EncID:      0x0,
								EncBaseID:  0x0,
							},
						},
					},
				},

				{
					tableKind: TypeRef,
					table: MetadataTable{
						Name:      "TypeRef",
						CountCols: 19,
						Content: []TypeRefTableRow{
							{
								ResolutionScope: 0x6,
								TypeName:        0x22bd,
								TypeNamespace:   0x4d80,
							},
						},
					},
				},

				{
					tableKind: MemberRef,
					table: MetadataTable{
						Name:      "MemberRef",
						CountCols: 17,
						Content: []MemberRefTableRow{
							{
								Class:     0x9,
								Name:      0x4c76,
								Signature: 0x1,
							},
						},
					},
				},

				{
					tableKind: CustomAttribute,
					table: MetadataTable{
						Name:      "CustomAttribute",
						CountCols: 19,
						Content: []CustomAttributeTableRow{
							{
								Parent: 0x27,
								Type:   0x83,
								Value:  0x2a1,
							},
						},
					},
				},

				{
					tableKind: DeclSecurity,
					table: MetadataTable{
						Name:      "DeclSecurity",
						CountCols: 1,
						Content: []DeclSecurityTableRow{
							{
								Action:        0x8,
								Parent:        0x6,
								PermissionSet: 0x52,
							},
						},
					},
				},

				{
					tableKind: Assembly,
					table: MetadataTable{
						Name:      "Assembly",
						CountCols: 1,
						Content: []AssemblyTableRow{
							{
								HashAlgId:      0x8004,
								MajorVersion:   0x4,
								MinorVersion:   0x0,
								BuildNumber:    0x0,
								RevisionNumber: 0x0,
								Flags:          0x1,
								PublicKey:      0x41,
								Name:           0x704,
								Culture:        0x0,
							},
						},
					},
				},

				{
					tableKind: AssemblyRef,
					table: MetadataTable{
						Name:      "AssemblyRef",
						CountCols: 30,
						Content: []AssemblyRefTableRow{
							{
								MajorVersion:     0x0,
								MinorVersion:     0x0,
								BuildNumber:      0x0,
								RevisionNumber:   0x0,
								Flags:            0x0,
								PublicKeyOrToken: 0x26,
								Name:             0x6ed,
								Culture:          0x0,
								HashValue:        0x0,
							},
						},
					},
				},

				{
					tableKind: ExportedType,
					table: MetadataTable{
						Name:      "ExportedType",
						CountCols: 1319,
						Content: []ExportedTypeTableRow{
							{
								Flags:          0x200000,
								TypeDefId:      0x0,
								TypeName:       0x5d85,
								TypeNamespace:  0x316,
								Implementation: 0x9,
							},
						},
					},
				},
			},
		},

		{
			getAbsoluteFilePath("test/pspluginwkr.dll"),
			[]TestClrMetadataTable{
				{
					tableKind: Module,
					table: MetadataTable{
						Name:      "Module",
						CountCols: 0x1,
						Content: []ModuleTableRow{
							{
								Generation: 0x0,
								Name:       0x8bdf,
								Mvid:       0x1,
								EncID:      0x0,
								EncBaseID:  0x0,
							},
						},
					},
				},

				{
					tableKind: TypeRef,
					table: MetadataTable{
						Name:      "TypeRef",
						CountCols: 140,
						Content: []TypeRefTableRow{
							{
								ResolutionScope: 0x6,
								TypeName:        0x1103,
								TypeNamespace:   0x1113,
							},
						},
					},
				},

				{
					tableKind: TypeDef,
					table: MetadataTable{
						Name:      "TypeDef",
						CountCols: 169,
						Content: []TypeDefTableRow{
							{
								Flags:         0x0,
								TypeName:      0x1,
								TypeNamespace: 0x0,
								Extends:       0x0,
								FieldList:     0x1,
								MethodList:    0x1,
							},
						},
					},
				},

				{
					tableKind: Field,
					table: MetadataTable{
						Name:      "Field",
						CountCols: 325,
						Content: []FieldTableRow{
							{
								Flags:     0x113,
								Name:      0x4af1,
								Signature: 0xea9,
							},
						},
					},
				},

				{
					tableKind: MethodDef,
					table: MetadataTable{
						Name:      "MethodDef",
						CountCols: 434,
						Content: []MethodDefTableRow{
							{
								RVA:       0x1d414,
								ImplFlags: 0x0,
								Flags:     0x13,
								Name:      0x1b7f,
								Signature: 0x125,
								ParamList: 0x1,
							},
						},
					},
				},

				{
					tableKind: Param,
					table: MetadataTable{
						Name:      "Param",
						CountCols: 679,
						Content: []ParamTableRow{
							{
								Flags:    0x2000,
								Sequence: 0x0,
								Name:     0x0,
							},
						},
					},
				},

				{
					tableKind: InterfaceImpl,
					table: MetadataTable{
						Name:      "InterfaceImpl",
						CountCols: 3,
						Content: []InterfaceImplTableRow{
							{
								Class:     0x6c,
								Interface: 0xa9,
							},
						},
					},
				},

				{
					tableKind: MemberRef,
					table: MetadataTable{
						Name:      "MemberRef",
						CountCols: 256,
						Content: []MemberRefTableRow{
							{
								Class:     0x29,
								Name:      0x79f8,
								Signature: 0x11e2,
							},
						},
					},
				},

				{
					tableKind: Constant,
					table: MetadataTable{
						Name:      "Constant",
						CountCols: 2,
						Content: []ConstantTableRow{
							{
								Type:   0xe,
								Parent: 0x464,
								Value:  0x1aa8,
							},
						},
					},
				},

				{
					tableKind: CustomAttribute,
					table: MetadataTable{
						Name:      "CustomAttribute",
						CountCols: 622,
						Content: []CustomAttributeTableRow{
							{
								Parent: 0x2e,
								Type:   0x7db,
								Value:  0x2c02,
							},
						},
					},
				},

				{
					tableKind: FieldMarshal,
					table: MetadataTable{
						Name:      "FieldMarshal",
						CountCols: 33,
						Content: []FieldMarshalTableRow{
							{
								Parent:     0x3,
								NativeType: 0x1ca6,
							},
						},
					},
				},

				{
					tableKind: DeclSecurity,
					table: MetadataTable{
						Name:      "DeclSecurity",
						CountCols: 4,
						Content: []DeclSecurityTableRow{
							{
								Action:        0x8,
								Parent:        0x6,
								PermissionSet: 0x2d81,
							},
						},
					},
				},

				{
					tableKind: ClassLayout,
					table: MetadataTable{
						Name:      "ClassLayout",
						CountCols: 144,
						Content: []ClassLayoutTableRow{
							{
								PackingSize: 0x0,
								ClassSize:   0x10,
								Parent:      0x2,
							},
						},
					},
				},

				{
					tableKind: StandAloneSig,
					table: MetadataTable{
						Name:      "StandAloneSig",
						CountCols: 358,
						Content: []StandAloneSigTableRow{
							{
								Signature: 0x1caa,
							},
						},
					},
				},

				{
					tableKind: EventMap,
					table: MetadataTable{
						Name:      "EventMap",
						CountCols: 2,
						Content: []EventMapTableRow{
							{
								Parent:    0x7f,
								EventList: 0x1,
							},
						},
					},
				},

				{
					tableKind: Event,
					table: MetadataTable{
						Name:      "Event",
						CountCols: 2,
						Content: []EventTableRow{
							{
								EventFlags: 0x200,
								Name:       0x7eeb,
								EventType:  0x16,
							},
						},
					},
				},

				{
					tableKind: PropertyMap,
					table: MetadataTable{
						Name:      "PropertyMap",
						CountCols: 2,
						Content: []PropertyMapTableRow{
							{
								Parent:       0x49,
								PropertyList: 0x1,
							},
						},
					},
				},

				{
					tableKind: Property,
					table: MetadataTable{
						Name:      "Property",
						CountCols: 2,
						Content: []PropertyTableRow{
							{
								Flags: 0x0,
								Name:  0x7a8a,
								Type:  0x11d7,
							},
						},
					},
				},

				{
					tableKind: MethodSemantics,
					table: MetadataTable{
						Name:      "MethodSemantics",
						CountCols: 9,
						Content: []MethodSemanticsTableRow{
							{
								Semantics:   0x10,
								Method:      0x153,
								Association: 0x2,
							},
						},
					},
				},

				{
					tableKind: ModuleRef,
					table: MetadataTable{
						Name:      "ModuleRef",
						CountCols: 1,
						Content: []ModuleRefTableRow{
							{
								Name: 0x0,
							},
						},
					},
				},

				{
					tableKind: TypeSpec,
					table: MetadataTable{
						Name:      "TypeSpec",
						CountCols: 17,
						Content: []TypeSpecTableRow{
							{
								Signature: 0x85,
							},
						},
					},
				},

				{
					tableKind: ImplMap,
					table: MetadataTable{
						Name:      "ImplMap",
						CountCols: 51,
						Content: []ImplMapTableRow{
							{
								MappingFlags:    0x240,
								MemberForwarded: 0x1cb,
								ImportName:      0x0,
								ImportScope:     0x1,
							},
						},
					},
				},

				{
					tableKind: FieldRVA,
					table: MetadataTable{
						Name:      "FieldRVA",
						CountCols: 265,
						Content: []FieldRVATableRow{
							{
								RVA:   0x11e4,
								Field: 0x1,
							},
						},
					},
				},

				{
					tableKind: Assembly,
					table: MetadataTable{
						Name:      "Assembly",
						CountCols: 1,
						Content: []AssemblyTableRow{
							{
								HashAlgId:      0x8004,
								MajorVersion:   0x1,
								MinorVersion:   0x0,
								BuildNumber:    0x0,
								RevisionNumber: 0x0,
								Flags:          0x1,
								PublicKey:      0x2b03,
								Name:           0x8bd3,
								Culture:        0x0,
							},
						},
					},
				},

				{
					tableKind: AssemblyRef,
					table: MetadataTable{
						Name:      "AssemblyRef",
						CountCols: 5,
						Content: []AssemblyRefTableRow{
							{
								MajorVersion:     0x2,
								MinorVersion:     0x0,
								BuildNumber:      0x0,
								RevisionNumber:   0x0,
								Flags:            0x0,
								PublicKeyOrToken: 0x1,
								Name:             0x10b9,
								Culture:          0x0,
								HashValue:        0xa,
							},
						},
					},
				},

				{
					tableKind: NestedClass,
					table: MetadataTable{
						Name:      "NestedClass",
						CountCols: 7,
						Content: []NestedClassTableRow{
							{
								NestedClass:    0x7,
								EnclosingClass: 0x6,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			var va, size uint32
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseCLRHeaderDirectory(va, size)
			if err != nil {
				t.Fatalf("parseCLRHeaderDirectory(%s) failed, reason: %v", tt.in, err)
			}

			clr := file.CLR
			for _, tbl := range tt.out {
				mdTable := clr.MetadataTables[tbl.tableKind]
				if mdTable.CountCols != tbl.table.CountCols {
					t.Errorf("CLR metadata tables assertion failed on %s table, got %v, want %v",
						tbl.table.Name, mdTable.CountCols, tbl.table.CountCols)
				}
				if mdTable.Name != tbl.table.Name {
					t.Errorf("CLR metadata tables assertion failed on %s table, got %v, want %v",
						tbl.table.Name, mdTable.Name, tbl.table)
				}

				var got, want interface{}
				switch mdTable.Content.(type) {
				case []ModuleTableRow:
					got = mdTable.Content.([]ModuleTableRow)[0]
					want = tbl.table.Content.([]ModuleTableRow)[0]
				case []TypeRefTableRow:
					got = mdTable.Content.([]TypeRefTableRow)[0]
					want = tbl.table.Content.([]TypeRefTableRow)[0]
				case []TypeDefTableRow:
					got = mdTable.Content.([]TypeDefTableRow)[0]
					want = tbl.table.Content.([]TypeDefTableRow)[0]
				case []MemberRefTableRow:
					got = mdTable.Content.([]MemberRefTableRow)[0]
					want = tbl.table.Content.([]MemberRefTableRow)[0]
				case []CustomAttributeTableRow:
					got = mdTable.Content.([]CustomAttributeTableRow)[0]
					want = tbl.table.Content.([]CustomAttributeTableRow)[0]
				case []DeclSecurityTableRow:
					got = mdTable.Content.([]DeclSecurityTableRow)[0]
					want = tbl.table.Content.([]DeclSecurityTableRow)[0]
				case []AssemblyTableRow:
					got = mdTable.Content.([]AssemblyTableRow)[0]
					want = tbl.table.Content.([]AssemblyTableRow)[0]
				case []AssemblyRefTableRow:
					got = mdTable.Content.([]AssemblyRefTableRow)[0]
					want = tbl.table.Content.([]AssemblyRefTableRow)[0]
				case []ExportedTypeTableRow:
					got = mdTable.Content.([]ExportedTypeTableRow)[0]
					want = tbl.table.Content.([]ExportedTypeTableRow)[0]
				case []FieldTableRow:
					got = mdTable.Content.([]FieldTableRow)[0]
					want = tbl.table.Content.([]FieldTableRow)[0]
				case []MethodDefTableRow:
					got = mdTable.Content.([]MethodDefTableRow)[0]
					want = tbl.table.Content.([]MethodDefTableRow)[0]
				case []ParamTableRow:
					got = mdTable.Content.([]ParamTableRow)[0]
					want = tbl.table.Content.([]ParamTableRow)[0]
				case []InterfaceImplTableRow:
					got = mdTable.Content.([]InterfaceImplTableRow)[0]
					want = tbl.table.Content.([]InterfaceImplTableRow)[0]
				case []ConstantTableRow:
					got = mdTable.Content.([]ConstantTableRow)[0]
					want = tbl.table.Content.([]ConstantTableRow)[0]
				case []FieldMarshalTableRow:
					got = mdTable.Content.([]FieldMarshalTableRow)[0]
					want = tbl.table.Content.([]FieldMarshalTableRow)[0]
				case []ClassLayoutTableRow:
					got = mdTable.Content.([]ClassLayoutTableRow)[0]
					want = tbl.table.Content.([]ClassLayoutTableRow)[0]
				case []StandAloneSigTableRow:
					got = mdTable.Content.([]StandAloneSigTableRow)[0]
					want = tbl.table.Content.([]StandAloneSigTableRow)[0]
				case []EventMapTableRow:
					got = mdTable.Content.([]EventMapTableRow)[0]
					want = tbl.table.Content.([]EventMapTableRow)[0]
				case []EventTableRow:
					got = mdTable.Content.([]EventTableRow)[0]
					want = tbl.table.Content.([]EventTableRow)[0]
				case []PropertyMapTableRow:
					got = mdTable.Content.([]PropertyMapTableRow)[0]
					want = tbl.table.Content.([]PropertyMapTableRow)[0]
				case []PropertyTableRow:
					got = mdTable.Content.([]PropertyTableRow)[0]
					want = tbl.table.Content.([]PropertyTableRow)[0]
				case []MethodSemanticsTableRow:
					got = mdTable.Content.([]MethodSemanticsTableRow)[0]
					want = tbl.table.Content.([]MethodSemanticsTableRow)[0]
				case []ModuleRefTableRow:
					got = mdTable.Content.([]ModuleRefTableRow)[0]
					want = tbl.table.Content.([]ModuleRefTableRow)[0]
				case []TypeSpecTableRow:
					got = mdTable.Content.([]TypeSpecTableRow)[0]
					want = tbl.table.Content.([]TypeSpecTableRow)[0]
				case []ImplMapTableRow:
					got = mdTable.Content.([]ImplMapTableRow)[0]
					want = tbl.table.Content.([]ImplMapTableRow)[0]
				case []FieldRVATableRow:
					got = mdTable.Content.([]FieldRVATableRow)[0]
					want = tbl.table.Content.([]FieldRVATableRow)[0]
				case []NestedClassTableRow:
					got = mdTable.Content.([]NestedClassTableRow)[0]
					want = tbl.table.Content.([]NestedClassTableRow)[0]
				default:
					got = "bad type"
					want = "good type"
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("CLR metadata tables assertion failed on %s table, got %v, want %v",
						tbl.table.Name, got, want)
				}

			}
		})
	}
}

func TestClrDirectorCOMImageFlagsType(t *testing.T) {

	tests := []struct {
		in  int
		out []string
	}{
		{
			0x9,
			[]string{"IL Only", "Strong Name Signed"},
		},
	}

	for _, tt := range tests {
		t.Run("CaseFlagsEqualTo_"+strconv.Itoa(tt.in), func(t *testing.T) {
			got := COMImageFlagsType(tt.in).String()
			sort.Strings(got)
			sort.Strings(tt.out)
			if !reflect.DeepEqual(got, tt.out) {
				t.Errorf("CLR header flags assertion failed, got %v, want %v",
					got, tt.out)
			}
		})
	}
}

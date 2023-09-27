package pe

const (
	// these are intentionally made so they do not collide with StringStream, GUIDStream, and BlobStream
	// they are used only for the getCodedIndexSize function
	idxStringStream = iota + 100
	idxGUIDStream
	idxBlobStream
)

type codedidx struct {
	tagbits uint8
	idx     []int
}

var (
	idxTypeDefOrRef        = codedidx{tagbits: 2, idx: []int{TypeDef, TypeRef, TypeSpec}}
	idxResolutionScope     = codedidx{tagbits: 2, idx: []int{Module, ModuleRef, AssemblyRef, TypeRef}}
	idxMemberRefParent     = codedidx{tagbits: 3, idx: []int{TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec}}
	idxHasConstant         = codedidx{tagbits: 2, idx: []int{Field, Param, Property}}
	idxHasCustomAttributes = codedidx{tagbits: 5, idx: []int{Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef, Module, Property, Event, StandAloneSig, ModuleRef, TypeSpec, Assembly, AssemblyRef, FileMD, ExportedType, ManifestResource}}
	idxCustomAttributeType = codedidx{tagbits: 3, idx: []int{MethodDef, MemberRef}}
	idxHasFieldMarshall    = codedidx{tagbits: 1, idx: []int{Field, Param}}
	idxHasDeclSecurity     = codedidx{tagbits: 2, idx: []int{TypeDef, MethodDef, Assembly}}
	idxHasSemantics        = codedidx{tagbits: 1, idx: []int{Event, Property}}
	idxMethodDefOrRef      = codedidx{tagbits: 1, idx: []int{MethodDef, MemberRef}}
	idxMemberForwarded     = codedidx{tagbits: 1, idx: []int{Field, MethodDef}}
	idxImplementation      = codedidx{tagbits: 2, idx: []int{AssemblyRef, ExportedType}}
	idxTypeOrMethodDef     = codedidx{tagbits: 1, idx: []int{TypeDef, MethodDef}}

	idxField        = codedidx{tagbits: 0, idx: []int{Field}}
	idxMethodDef    = codedidx{tagbits: 0, idx: []int{MethodDef}}
	idxParam        = codedidx{tagbits: 0, idx: []int{Param}}
	idxTypeDef      = codedidx{tagbits: 0, idx: []int{TypeDef}}
	idxEvent        = codedidx{tagbits: 0, idx: []int{Event}}
	idxProperty     = codedidx{tagbits: 0, idx: []int{Property}}
	idxModuleRef    = codedidx{tagbits: 0, idx: []int{ModuleRef}}
	idxGenericParam = codedidx{tagbits: 0, idx: []int{GenericParam}}

	idxString = codedidx{tagbits: 0, idx: []int{idxStringStream}}
	idxBlob   = codedidx{tagbits: 0, idx: []int{idxBlobStream}}
	idxGUID   = codedidx{tagbits: 0, idx: []int{idxGUIDStream}}
)

func (pe *File) getCodedIndexSize(tagbits uint32, idx ...int) uint32 {
	// special case String/GUID/Blob streams
	switch idx[0] {
	case int(idxStringStream):
		return uint32(pe.GetMetadataStreamIndexSize(StringStream))
	case int(idxGUIDStream):
		return uint32(pe.GetMetadataStreamIndexSize(GUIDStream))
	case int(idxBlobStream):
		return uint32(pe.GetMetadataStreamIndexSize(BlobStream))
	}

	// now deal with coded indices or single table
	var maxIndex16 uint32 = 1 << (16 - tagbits)
	var maxColumnCount uint32
	for _, tblidx := range idx {
		tbl, ok := pe.CLR.MetadataTables[tblidx]
		if ok {
			if tbl.CountCols > maxColumnCount {
				maxColumnCount = tbl.CountCols
			}
		}
	}
	if maxColumnCount > maxIndex16 {
		return 4
	}
	return 2
}

func (pe *File) readFromMetadataStream(cidx codedidx, off uint32, out *uint32) (uint32, error) {
	indexSize := pe.getCodedIndexSize(uint32(cidx.tagbits), cidx.idx...)
	var data uint32
	var err error
	switch indexSize {
	case 2:
		d, err := pe.ReadUint16(off)
		if err != nil {
			return 0, err
		}
		data = uint32(d)
	case 4:
		data, err = pe.ReadUint32(off)
		if err != nil {
			return 0, err
		}
	}

	*out = data
	return uint32(indexSize), nil
}

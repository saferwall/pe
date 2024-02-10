// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"strconv"
)

const (
	// Unwind information flags.

	// UnwFlagNHandler - The function has no handler.
	UnwFlagNHandler = uint8(0x0)

	// UnwFlagEHandler - The function has an exception handler that should
	// be called when looking for functions that need to examine exceptions.
	UnwFlagEHandler = uint8(0x1)

	// UnwFlagUHandler - The function has a termination handler that should
	// be called when unwinding an exception.
	UnwFlagUHandler = uint8(0x2)

	// UnwFlagChainInfo - This unwind info structure is not the primary one
	// for the procedure. Instead, the chained unwind info entry is the contents
	// of a previous RUNTIME_FUNCTION entry. For information, see Chained unwind
	// info structures. If this flag is set, then the UNW_FLAG_EHANDLER and
	// UNW_FLAG_UHANDLER flags must be cleared. Also, the frame register and
	// fixed-stack allocation field must have the same values as in the primary
	// unwind info.
	UnwFlagChainInfo = uint8(0x4)
)

// The meaning of the operation info bits depends upon the operation code.
// To encode a general-purpose (integer) register, this mapping is used:
const (
	rax = iota
	rcx
	rdx
	rbx
	rsp
	rbp
	rsi
	rdi
	r8
	r9
	r10
	r11
	r12
	r13
	r14
	r15
)

// OpInfoRegisters maps registers to string.
var OpInfoRegisters = map[uint8]string{
	rax: "RAX",
	rcx: "RCX",
	rdx: "RDX",
	rbx: "RBX",
	rsp: "RSP",
	rbp: "RBP",
	rsi: "RSI",
	rdi: "RDI",
	r8:  "R8",
	r9:  "R9",
	r10: "R10",
	r11: "R11",
	r12: "R12",
	r13: "R13",
	r14: "R14",
	r15: "R15",
}

// UnwindOpType represents the type of an unwind opcode.
type UnwindOpType uint8

// _UNWIND_OP_CODES
const (
	// Push a nonvolatile integer register, decrementing RSP by 8. The
	// operation info is the number of the register. Because of the constraints
	// on epilogs, UWOP_PUSH_NONVOL unwind codes must appear first in the
	// prolog and correspondingly, last in the unwind code array. This relative
	// ordering applies to all other unwind codes except UWOP_PUSH_MACHFRAME.
	UwOpPushNonVol = UnwindOpType(0)

	// Allocate a large-sized area on the stack. There are two forms. If the
	// operation info equals 0, then the size of the allocation divided by 8 is
	// recorded in the next slot, allowing an allocation up to 512K - 8. If the
	// operation info equals 1, then the unscaled size of the allocation is
	// recorded in the next two slots in little-endian format, allowing
	// allocations up to 4GB - 8.
	UwOpAllocLarge = UnwindOpType(1)

	// Allocate a small-sized area on the stack. The size of the allocation is
	// the operation info field * 8 + 8, allowing allocations from 8 to 128
	// bytes.
	UwOpAllocSmall = UnwindOpType(2)

	// Establish the frame pointer register by setting the register to some
	// offset of the current RSP. The offset is equal to the Frame Register
	// offset (scaled) field in the UNWIND_INFO * 16, allowing offsets from 0
	// to 240. The use of an offset permits establishing a frame pointer that
	// points to the middle of the fixed stack allocation, helping code density
	// by allowing more accesses to use short instruction forms. The operation
	// info field is reserved and shouldn't be used.
	UwOpSetFpReg = UnwindOpType(3)

	// Save a nonvolatile integer register on the stack using a MOV instead of
	// a PUSH. This code is primarily used for shrink-wrapping, where a
	// nonvolatile register is saved to the stack in a position that was
	// previously allocated. The operation info is the number of the register.
	// The scaled-by-8 stack offset is recorded in the next unwind operation
	// code slot, as described in the note above.
	UwOpSaveNonVol = UnwindOpType(4)

	// Save a nonvolatile integer register on the stack with a long offset,
	// using a MOV instead of a PUSH. This code is primarily used for
	// shrink-wrapping, where a nonvolatile register is saved to the stack in a
	// position that was previously allocated. The operation info is the number
	// of the register. The unscaled stack offset is recorded in the next two
	// unwind operation code slots, as described in the note above.
	UwOpSaveNonVolFar = UnwindOpType(5)

	// For version 1 of the UNWIND_INFO structure, this code was called
	// UWOP_SAVE_XMM and occupied 2 records, it retained the lower 64 bits of
	// the XMM register, but was later removed and is now skipped. In practice,
	// this code has never been used.
	// For version 2 of the UNWIND_INFO structure, this code is called
	// UWOP_EPILOG, takes 2 entries, and describes the function epilogue.
	UwOpEpilog = UnwindOpType(6)

	// For version 1 of the UNWIND_INFO structure, this code was called
	// UWOP_SAVE_XMM_FAR and occupied 3 records, it saved the lower 64 bits of
	// the XMM register, but was later removed and is now skipped. In practice,
	// this code has never been used.
	// For version 2 of the UNWIND_INFO structure, this code is called
	// UWOP_SPARE_CODE, takes 3 entries, and makes no sense.
	UwOpSpareCode = UnwindOpType(7)

	// Save all 128 bits of a nonvolatile XMM register on the stack. The
	// operation info is the number of the register. The scaled-by-16 stack
	// offset is recorded in the next slot.
	UwOpSaveXmm128 = UnwindOpType(8)

	// Save all 128 bits of a nonvolatile XMM register on the stack with a long
	// offset. The operation info is the number of the register. The unscaled
	// stack offset is recorded in the next two slots.
	UwOpSaveXmm128Far = UnwindOpType(9)

	// Push a machine frame. This unwind code is used to record the effect of a
	// hardware interrupt or exception.
	UwOpPushMachFrame = UnwindOpType(10)

	// UWOP_SET_FPREG_LARGE is a CLR Unix-only extension to the Windows AMD64
	// unwind codes. It is not part of the standard Windows AMD64 unwind codes
	// specification. UWOP_SET_FPREG allows for a maximum of a 240 byte offset
	// between RSP and the frame pointer, when the frame pointer is
	// established. UWOP_SET_FPREG_LARGE has a 32-bit range scaled by 16. When
	// UWOP_SET_FPREG_LARGE is used, UNWIND_INFO.FrameRegister must be set to
	// the frame pointer register, and UNWIND_INFO.FrameOffset must be set to
	// 15 (its maximum value). UWOP_SET_FPREG_LARGE is followed by two
	// UNWIND_CODEs that are combined to form a 32-bit offset (the same as
	// UWOP_SAVE_NONVOL_FAR). This offset is then scaled by 16. The result must
	// be less than 2^32 (that is, the top 4 bits of the unscaled 32-bit number
	// must be zero). This result is used as the frame pointer register offset
	// from RSP at the time the frame pointer is established. Either
	// UWOP_SET_FPREG or UWOP_SET_FPREG_LARGE can be used, but not both.
	UwOpSetFpRegLarge = UnwindOpType(11)
)

// ImageRuntimeFunctionEntry represents an entry in the function table on 64-bit
// Windows (IMAGE_RUNTIME_FUNCTION_ENTRY). Table-based exception handling request
// a table entry for all functions that allocate stack space or call another
// function (for example, non-leaf functions).
type ImageRuntimeFunctionEntry struct {
	// The address of the start of the function.
	BeginAddress uint32 `json:"begin_address"`

	// The address of the end of the function.
	EndAddress uint32 `json:"end_address"`

	// The unwind data info structure is used to record the effects a function
	// has on the stack pointer, and where the nonvolatile registers are saved
	// on the stack.
	UnwindInfoAddress uint32 `json:"unwind_info_address"`
}

// ImageARMRuntimeFunctionEntry represents the function table entry for the ARM
// platform.
type ImageARMRuntimeFunctionEntry struct {
	// Function Start RVA is the 32-bit RVA of the start of the function. If
	// the function contains thumb code, the low bit of this address must be set.
	BeginAddress uint32 `bitfield:",functionstart" json:"begin_address"`

	// Flag is a 2-bit field that indicates how to interpret the remaining
	// 30 bits of the second .pdata word. If Flag is 0, then the remaining bits
	// form an Exception Information RVA (with the low two bits implicitly 0).
	// If Flag is non-zero, then the remaining bits form a Packed Unwind Data
	// structure.
	Flag uint8 `json:"flag"`

	/* Exception Information RVA or Packed Unwind Data.

	Exception Information RVA is the address of the variable-length exception
	information structure, stored in the .xdata section.
	This data must be 4-byte aligned.

	Packed Unwind Data is a compressed description of the operations required
	to unwind from a function, assuming a canonical form. In this case, no
	.xdata record is required. */
	ExceptionFlag uint32 `json:"exception_flag"`
}

// UnwindCode is used to record the sequence of operations in the prolog that
// affect the nonvolatile registers and RSP. Each code item has this format:
/* typedef union _UNWIND_CODE {
    struct {
        UCHAR CodeOffset;
        UCHAR UnwindOp : 4;
        UCHAR OpInfo : 4;
    } DUMMYUNIONNAME;

    struct {
        UCHAR OffsetLow;
        UCHAR UnwindOp : 4;
        UCHAR OffsetHigh : 4;
    } EpilogueCode;

    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;*/
//
// It provides information about the amount of stack space allocated, the location
// of saved non-volatile registers, and whether or not a frame register is used
// and what relation it has to the rest of the stack.
type UnwindCode struct {
	// Offset (from the beginning of the prolog) of the end of the instruction
	// that performs is operation, plus 1 (that is, the offset of the start of
	// the next instruction).
	CodeOffset uint8 `json:"code_offset"`

	// The unwind operation code.
	UnwindOp UnwindOpType `json:"unwind_op"`

	// Operation info.
	OpInfo uint8 `json:"op_info"`

	// Allocation size.
	Operand     string `json:"operand"`
	FrameOffset uint16 `json:"frame_offset"`
}

// UnwindInfo represents the _UNWIND_INFO structure. It is used to record the
// effects a function has on the stack pointer, and where the nonvolatile
// registers are saved on the stack.
type UnwindInfo struct {
	// (3 bits) Version number of the unwind data, currently 1 and 2.
	Version uint8 `json:"version"`

	// (5 bits) Three flags are currently defined above.
	Flags uint8 `json:"flags"`

	// Length of the function prolog in bytes.
	SizeOfProlog uint8 `json:"size_of_prolog"`

	// The number of slots in the unwind codes array. Some unwind codes,
	// for example, UWOP_SAVE_NONVOL, require more than one slot in the array.
	CountOfCodes uint8 `json:"count_of_codes"`

	// If nonzero, then the function uses a frame pointer (FP), and this field
	// is the number of the nonvolatile register used as the frame pointer,
	// using the same encoding for the operation info field of UNWIND_CODE nodes.
	FrameRegister uint8 `json:"frame_register"`

	// If the frame register field is nonzero, this field is the scaled offset
	// from RSP that is applied to the FP register when it's established. The
	// actual FP register is set to RSP + 16 * this number, allowing offsets
	// from 0 to 240. This offset permits pointing the FP register into the
	// middle of the local stack allocation for dynamic stack frames, allowing
	// better code density through shorter instructions. (That is, more
	// instructions can use the 8-bit signed offset form.)
	FrameOffset uint8 `json:"frame_offset"`

	// An array of items that explains the effect of the prolog on the
	// nonvolatile registers and RSP. See the section on UNWIND_CODE for the
	// meanings of individual items. For alignment purposes, this array always
	// has an even number of entries, and the final entry is potentially
	// unused. In that case, the array is one longer than indicated by the
	// count of unwind codes field.
	UnwindCodes []UnwindCode `json:"unwind_codes"`

	// Address of exception handler when UNW_FLAG_EHANDLER is set.
	ExceptionHandler uint32 `json:"exception_handler"`

	// If flag UNW_FLAG_CHAININFO is set, then the UNWIND_INFO structure ends
	// with three UWORDs. These UWORDs represent the RUNTIME_FUNCTION
	// information for the function of the chained unwind.
	FunctionEntry ImageRuntimeFunctionEntry `json:"function_entry"`
}

//
// The unwind codes are followed by an optional DWORD aligned field that
// contains the exception handler address or the address of chained unwind
// information. If an exception handler address is specified, then it is
// followed by the language specified exception handler data.
//
//  union {
//      ULONG ExceptionHandler;
//      ULONG FunctionEntry;
//  };
//
//  ULONG ExceptionData[];
//

type ScopeRecord struct {
	// This value indicates the offset of the first instruction within a __try
	// block located in the function.
	BeginAddress uint32 `json:"begin_address"`

	// This value indicates the offset to the instruction after the last
	// instruction within the __try block (conceptually the __except statement).
	EndAddress uint32 `json:"end_address"`

	// This value indicates the offset to the function located within the
	// parentheses of the __except() statement. In the documentation you'll
	// find this routine called the "exception handler" or "exception filter".
	HandlerAddress uint32 `json:"handler_address"`

	// This value indicates the offset to the first instruction in the __except
	// block associated with the __try block.
	JumpTarget uint32 `json:"jump_target"`
}

// ScopeTable represents a variable length structure containing a count followed
// by Count "scope records". While the RUNTIME_FUNCTION describes the entire range
// of a function that contains SEH, the SCOPE_TABLE describes each of the individual
// __try/__except blocks within the function.
type ScopeTable struct {
	// The count of scope records.
	Count uint32 `json:"count"`

	// A array of scope record.
	ScopeRecords []ScopeRecord `json:"scope_records"`
}

//  typedef struct _SCOPE_TABLE {
// 		ULONG Count;
// 		struct
// 		{
// 			ULONG BeginAddress;
// 			ULONG EndAddress;
// 			ULONG HandlerAddress;
// 			ULONG JumpTarget;
// 		} ScopeRecord[1];
//  } SCOPE_TABLE, *PSCOPE_TABLE;

// Exception represent an entry in the function table.
type Exception struct {
	RuntimeFunction ImageRuntimeFunctionEntry `json:"runtime_function"`
	UnwindInfo      UnwindInfo                `json:"unwind_info"`
}

func (pe *File) parseUnwindCode(offset uint32, version uint8) (UnwindCode, int) {

	unwindCode := UnwindCode{}
	advanceBy := 0

	// Read the unwind code at offset (2 bytes)
	uc, err := pe.ReadUint16(offset)
	if err != nil {
		return unwindCode, advanceBy
	}

	unwindCode.CodeOffset = uint8(uc & 0xff)
	unwindCode.UnwindOp = UnwindOpType(uc & 0xf00 >> 8)
	unwindCode.OpInfo = uint8(uc & 0xf000 >> 12)

	switch unwindCode.UnwindOp {
	case UwOpAllocSmall:
		size := int(unwindCode.OpInfo*8 + 8)
		unwindCode.Operand = "Size=" + strconv.Itoa(size)
		advanceBy++
	case UwOpAllocLarge:
		if unwindCode.OpInfo == 0 {
			size := int(binary.LittleEndian.Uint16(pe.data[offset+2:]) * 8)
			unwindCode.Operand = "Size=" + strconv.Itoa(size)
			advanceBy += 2
		} else {
			size := int(binary.LittleEndian.Uint32(pe.data[offset+2:]) << 16)
			unwindCode.Operand = "Size=" + strconv.Itoa(size)
			advanceBy += 3
		}
	case UwOpSetFpReg:
		unwindCode.Operand = "Register=" + OpInfoRegisters[unwindCode.OpInfo]
		advanceBy++
	case UwOpPushNonVol:
		unwindCode.Operand = "Register=" + OpInfoRegisters[unwindCode.OpInfo]
		advanceBy++
	case UwOpSaveNonVol:
		fo := binary.LittleEndian.Uint16(pe.data[offset+2:])
		unwindCode.FrameOffset = fo * 8
		unwindCode.Operand = "Register=" + OpInfoRegisters[unwindCode.OpInfo] +
			", Offset=" + strconv.Itoa(int(unwindCode.FrameOffset))
		advanceBy += 2
	case UwOpSaveNonVolFar:
		fo := binary.LittleEndian.Uint32(pe.data[offset+2:])
		unwindCode.FrameOffset = uint16(fo * 8)
		unwindCode.Operand = "Register=" + OpInfoRegisters[unwindCode.OpInfo] +
			", Offset=" + strconv.Itoa(int(unwindCode.FrameOffset))
		advanceBy += 3
	case UwOpSaveXmm128:
		fo := binary.LittleEndian.Uint16(pe.data[offset+2:])
		unwindCode.FrameOffset = fo * 16
		unwindCode.Operand = "Register=XMM" + strconv.Itoa(int(unwindCode.OpInfo)) +
			", Offset=" + strconv.Itoa(int(unwindCode.FrameOffset))
		advanceBy += 2
	case UwOpSaveXmm128Far:
		fo := binary.LittleEndian.Uint32(pe.data[offset+2:])
		unwindCode.FrameOffset = uint16(fo)
		unwindCode.Operand = "Register=XMM" + strconv.Itoa(int(unwindCode.OpInfo)) +
			", Offset=" + strconv.Itoa(int(unwindCode.FrameOffset))
		advanceBy += 3
	case UwOpSetFpRegLarge:
		unwindCode.Operand = "Register=" + OpInfoRegisters[unwindCode.OpInfo]
		advanceBy += 2
	case UwOpPushMachFrame:
		advanceBy++
	case UwOpEpilog:
		if version == 2 {
			unwindCode.Operand = "Flags=" + strconv.Itoa(int(unwindCode.OpInfo)) + ", Size=" + strconv.Itoa(int(unwindCode.CodeOffset))
		}
		advanceBy += 2
	case UwOpSpareCode:
		advanceBy += 3
	default:
		advanceBy++ // so we can get out of the loop
		pe.logger.Warnf("Wrong unwind opcode %d", unwindCode.UnwindOp)
	}

	return unwindCode, advanceBy
}

func (pe *File) parseUnwindInfo(unwindInfo uint32) UnwindInfo {

	ui := UnwindInfo{}

	offset := pe.GetOffsetFromRva(unwindInfo)
	v, err := pe.ReadUint32(offset)
	if err != nil {
		return ui
	}

	// The lowest 3 bits
	ui.Version = uint8(v & 0x7)

	// The next 5 bits.
	ui.Flags = uint8(v & 0xf8 >> 3)

	// The next byte
	ui.SizeOfProlog = uint8(v & 0xff00 >> 8)

	// The next byte
	ui.CountOfCodes = uint8(v & 0xff0000 >> 16)

	// The next 4 bits
	ui.FrameRegister = uint8(v & 0xf00000 >> 24)

	// The next 4 bits.
	ui.FrameOffset = uint8(v&0xf0000000>>28) * 6

	// Each unwind code struct is 2 bytes wide.
	offset += 4
	i := 0
	for i < int(ui.CountOfCodes) {
		ucOffset := offset + 2*uint32(i)
		unwindCode, advanceBy := pe.parseUnwindCode(ucOffset, ui.Version)
		if advanceBy == 0 {
			return ui
		}
		ui.UnwindCodes = append(ui.UnwindCodes, unwindCode)
		i += advanceBy
	}

	if ui.CountOfCodes&1 == 1 {
		offset += 2
	}

	// An image-relative pointer to either the function's language-specific
	// exception or termination handler, if flag UNW_FLAG_CHAININFO is clear
	// and one of the flags UNW_FLAG_EHADLER or UNW_FLAG_UHANDLER is set.
	if ui.Flags&UnwFlagEHandler != 0 || ui.Flags&UnwFlagUHandler != 0 {
		if ui.Flags&UnwFlagChainInfo == 0 {
			handlerOffset := offset + 2*uint32(i)
			ui.ExceptionHandler = binary.LittleEndian.Uint32(pe.data[handlerOffset:])
		}
	}

	// If the UNW_FLAG_CHAININFO flag is set, then an unwind info structure
	// is a secondary one, and the shared exception-handler/chained-info
	// address field contains the primary unwind information. This sample
	// code retrieves the primary unwind information, assuming that unwindInfo
	// is the structure that has the UNW_FLAG_CHAININFO flag set.
	if ui.Flags&UnwFlagChainInfo != 0 {
		chainOffset := offset + 2*uint32(i)
		rf := ImageRuntimeFunctionEntry{}
		size := uint32(binary.Size(ImageRuntimeFunctionEntry{}))
		err := pe.structUnpack(&rf, chainOffset, size)
		if err != nil {
			return ui
		}
		ui.FunctionEntry = rf
	}

	return ui
}

// Exception directory contains an array of function table entries that are used
// for exception handling.
func (pe *File) parseExceptionDirectory(rva, size uint32) error {

	// The target platform determines which format of the function table entry
	// to use.
	var exceptions []Exception
	fileOffset := pe.GetOffsetFromRva(rva)

	entrySize := uint32(binary.Size(ImageRuntimeFunctionEntry{}))
	entriesCount := size / entrySize

	for i := uint32(0); i < entriesCount; i++ {
		functionEntry := ImageRuntimeFunctionEntry{}
		offset := fileOffset + (entrySize * i)
		err := pe.structUnpack(&functionEntry, offset, entrySize)
		if err != nil {
			return err
		}

		exception := Exception{RuntimeFunction: functionEntry}

		if pe.Is64 {
			exception.UnwindInfo = pe.parseUnwindInfo(functionEntry.UnwindInfoAddress)
		}

		exceptions = append(exceptions, exception)
	}

	pe.Exceptions = exceptions
	if len(exceptions) > 0 {
		pe.HasException = true
	}
	return nil
}

// PrettyUnwindInfoHandlerFlags returns the string representation of the
// `flags` field of the unwind info structure.
func PrettyUnwindInfoHandlerFlags(flags uint8) []string {
	var values []string

	unwFlagHandlerMap := map[uint8]string{
		UnwFlagNHandler:  "No Handler",
		UnwFlagEHandler:  "Exception",
		UnwFlagUHandler:  "Termination",
		UnwFlagChainInfo: "Chain",
	}

	for k, s := range unwFlagHandlerMap {
		if k&flags != 0 {
			values = append(values, s)
		}
	}
	return values
}

// String returns the string representation of the an unwind opcode.
func (uo UnwindOpType) String() string {

	unOpToString := map[UnwindOpType]string{
		UwOpPushNonVol:    "UWOP_PUSH_NONVOL",
		UwOpAllocLarge:    "UWOP_ALLOC_LARE",
		UwOpAllocSmall:    "UWOP_ALLOC_SMALL",
		UwOpSetFpReg:      "UWOP_SET_FPREG",
		UwOpSaveNonVol:    "UWOP_SAVE_NONVOL",
		UwOpSaveNonVolFar: "UWOP_SAVE_NONVOL_FAR",
		UwOpEpilog:        "UWOP_EPILOG",
		UwOpSpareCode:     "UWOP_SPARE_CODE",
		UwOpSaveXmm128:    "UWOP_SAVE_XMM128",
		UwOpSaveXmm128Far: "UWOP_SAVE_XMM128_FAR",
		UwOpPushMachFrame: "UWOP_PUSH_MACHFRAME",
		UwOpSetFpRegLarge: "UWOP_SET_FPREG_LARGE",
	}

	if val, ok := unOpToString[uo]; ok {
		return val
	}

	return "?"
}

// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

// References:
// https://www.virtualbox.org/svn/vbox/trunk/include/iprt/formats/pecoff.h
// https://github.com/hdoc/llvm-project/blob/release/15.x/llvm/include/llvm/Object/COFF.h
// https://ffri.github.io/ProjectChameleon/new_reloc_chpev2/
// https://blogs.blackberry.com/en/2019/09/teardown-windows-10-on-arm-x86-emulation
// DVRT: https://www.alex-ionescu.com/?p=323
// https://xlab.tencent.com/en/2016/11/02/return-flow-guard/
// https://denuvosoftwaresolutions.github.io/DVRT/dvrt.html
// BlueHat v18 || Retpoline: The Anti sectre type 2 mitigation in windows: https://www.youtube.com/watch?v=ZfxXjDQRpsU

package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

// ImageGuardFlagType represents the type for load configuration image guard flags.
type ImageGuardFlagType uint8

// GFIDS table entry flags.
const (
	// ImageGuardFlagFIDSuppressed indicates that the call target is explicitly
	// suppressed (do not treat it as valid for purposes of CFG).
	ImageGuardFlagFIDSuppressed = 0x1

	// ImageGuardFlagExportSuppressed indicates that the call target is export
	// suppressed. See Export suppression for more details.
	ImageGuardFlagExportSuppressed = 0x2
)

// The GuardFlags field contains a combination of one or more of the
// following flags and subfields:
const (
	// ImageGuardCfInstrumented indicates that the module performs control flow
	// integrity checks using system-supplied support.
	ImageGuardCfInstrumented = 0x00000100

	// ImageGuardCfWInstrumented indicates that the module performs control
	// flow and write integrity checks.
	ImageGuardCfWInstrumented = 0x00000200

	// ImageGuardCfFunctionTablePresent indicates that the module contains
	// valid control flow target metadata.
	ImageGuardCfFunctionTablePresent = 0x00000400

	// ImageGuardSecurityCookieUnused indicates that the module does not make
	// use of the /GS security cookie.
	ImageGuardSecurityCookieUnused = 0x00000800

	// ImageGuardProtectDelayLoadIAT indicates that the module supports read
	// only delay load IAT.
	ImageGuardProtectDelayLoadIAT = 0x00001000

	// ImageGuardDelayLoadIATInItsOwnSection indicates that the Delayload
	// import table in its own .didat section (with nothing else in it) that
	// can be freely reprotected.
	ImageGuardDelayLoadIATInItsOwnSection = 0x00002000

	// ImageGuardCfExportSuppressionInfoPresent indicates that the module
	// contains suppressed export information. This also infers that the
	// address taken IAT table is also present in the load config.
	ImageGuardCfExportSuppressionInfoPresent = 0x00004000

	// ImageGuardCfEnableExportSuppression indicates that the module enables
	// suppression of exports.
	ImageGuardCfEnableExportSuppression = 0x00008000

	// ImageGuardCfLongJumpTablePresent indicates that the module contains
	// long jmp target information.
	ImageGuardCfLongJumpTablePresent = 0x00010000
)

const (
	// ImageGuardCfFunctionTableSizeMask indicates that the mask for the
	// subfield that contains the stride of Control Flow Guard function table
	// entries (that is, the additional count of bytes per table entry).
	ImageGuardCfFunctionTableSizeMask = 0xF0000000

	// ImageGuardCfFunctionTableSizeShift indicates the shift to right-justify
	// Guard CF function table stride.
	ImageGuardCfFunctionTableSizeShift = 28
)

const (
	ImageDynamicRelocationGuardRfPrologue = 0x00000001
	ImageDynamicRelocationGuardREpilogue  = 0x00000002
)

// Software enclave information.
const (
	ImageEnclaveLongIDLength  = 32
	ImageEnclaveShortIDLength = 16
)

const (
	// ImageEnclaveImportMatchNone indicates that none of the identifiers of the
	// image need to match the value in the import record.
	ImageEnclaveImportMatchNone = 0x00000000

	// ImageEnclaveImportMatchUniqueId indicates that the value of the enclave
	// unique identifier of the image must match the value in the import record.
	// Otherwise, loading of the image fails.
	ImageEnclaveImportMatchUniqueID = 0x00000001

	// ImageEnclaveImportMatchAuthorId indicates that the value of the enclave
	// author identifier of the image must match the value in the import record.
	// Otherwise, loading of the image fails. If this flag is set and the import
	// record indicates an author identifier of all zeros, the imported image
	// must be part of the Windows installation.
	ImageEnclaveImportMatchAuthorID = 0x00000002

	// ImageEnclaveImportMatchFamilyId indicates that the value of the enclave
	// family identifier of the image must match the value in the import record.
	// Otherwise, loading of the image fails.
	ImageEnclaveImportMatchFamilyID = 0x00000003

	// ImageEnclaveImportMatchImageId indicates that the value of the enclave
	// image identifier must match the value in the import record. Otherwise,
	// loading of the image fails.
	ImageEnclaveImportMatchImageID = 0x00000004
)

// ImageLoadConfigDirectory32 Contains the load configuration data of an image for x86 binaries.
type ImageLoadConfigDirectory32 struct {
	// The actual size of the structure inclusive. May differ from the size
	// given in the data directory for Windows XP and earlier compatibility.
	Size uint32 `json:"size"`

	// Date and time stamp value.
	TimeDateStamp uint32 `json:"time_date_stamp"`

	// Major version number.
	MajorVersion uint16 `json:"major_version"`

	// Minor version number.
	MinorVersion uint16 `json:"minor_version"`

	// The global loader flags to clear for this process as the loader starts
	// the process.
	GlobalFlagsClear uint32 `json:"global_flags_clear"`

	// The global loader flags to set for this process as the loader starts the
	// process.
	GlobalFlagsSet uint32 `json:"global_flags_set"`

	// The default timeout value to use for this process's critical sections
	// that are abandoned.
	CriticalSectionDefaultTimeout uint32 `json:"critical_section_default_timeout"`

	// Memory that must be freed before it is returned to the system, in bytes.
	DeCommitFreeBlockThreshold uint32 `json:"de_commit_free_block_threshold"`

	// Total amount of free memory, in bytes.
	DeCommitTotalFreeThreshold uint32 `json:"de_commit_total_free_threshold"`

	// [x86 only] The VA of a list of addresses where the LOCK prefix is used so
	// that they can be replaced with NOP on single processor machines.
	LockPrefixTable uint32 `json:"lock_prefix_table"`

	// Maximum allocation size, in bytes.
	MaximumAllocationSize uint32 `json:"maximum_allocation_size"`

	// Maximum virtual memory size, in bytes.
	VirtualMemoryThreshold uint32 `json:"virtual_memory_threshold"`

	// Process heap flags that correspond to the first argument of the HeapCreate
	// function. These flags apply to the process heap that is created during
	// process startup.
	ProcessHeapFlags uint32 `json:"process_heap_flags"`

	// Setting this field to a non-zero value is equivalent to calling
	// SetProcessAffinityMask with this value during process startup (.exe only)
	ProcessAffinityMask uint32 `json:"process_affinity_mask"`

	// The service pack version identifier.
	CSDVersion uint16 `json:"csd_version"`

	// Must be zero.
	DependentLoadFlags uint16 `json:"dependent_load_flags"`

	// Reserved for use by the system.
	EditList uint32 `json:"edit_list"`

	// A pointer to a cookie that is used by Visual C++ or GS implementation.
	SecurityCookie uint32 `json:"security_cookie"`

	// [x86 only] The VA of the sorted table of RVAs of each valid, unique SE
	// handler in the image.
	SEHandlerTable uint32 `json:"se_handler_table"`

	// [x86 only] The count of unique handlers in the table.
	SEHandlerCount uint32 `json:"se_handler_count"`

	// The VA where Control Flow Guard check-function pointer is stored.
	GuardCFCheckFunctionPointer uint32 `json:"guard_cf_check_function_pointer"`

	// The VA where Control Flow Guard dispatch-function pointer is stored.
	GuardCFDispatchFunctionPointer uint32 `json:"guard_cf_dispatch_function_pointer"`

	// The VA of the sorted table of RVAs of each Control Flow Guard function in
	// the image.
	GuardCFFunctionTable uint32 `json:"guard_cf_function_table"`

	// The count of unique RVAs in the above table.
	GuardCFFunctionCount uint32 `json:"guard_cf_function_count"`

	// Control Flow Guard related flags.
	GuardFlags uint32 `json:"guard_flags"`

	// Code integrity information.
	CodeIntegrity ImageLoadConfigCodeIntegrity `json:"code_integrity"`

	// The VA where Control Flow Guard address taken IAT table is stored.
	GuardAddressTakenIATEntryTable uint32 `json:"guard_address_taken_iat_entry_table"`

	// The count of unique RVAs in the above table.
	GuardAddressTakenIATEntryCount uint32 `json:"guard_address_taken_iat_entry_count"`

	// The VA where Control Flow Guard long jump target table is stored.
	GuardLongJumpTargetTable uint32 `json:"guard_long_jump_target_table"`

	// The count of unique RVAs in the above table.
	GuardLongJumpTargetCount uint32 `json:"guard_long_jump_target_count"`

	DynamicValueRelocTable uint32 `json:"dynamic_value_reloc_table"`

	// Not sure when this was renamed from HybridMetadataPointer.
	CHPEMetadataPointer uint32 `json:"chpe_metadata_pointer"`

	GuardRFFailureRoutine                    uint32 `json:"guard_rf_failure_routine"`
	GuardRFFailureRoutineFunctionPointer     uint32 `json:"guard_rf_failure_routine_function_pointer"`
	DynamicValueRelocTableOffset             uint32 `json:"dynamic_value_reloc_table_offset"`
	DynamicValueRelocTableSection            uint16 `json:"dynamic_value_reloc_table_section"`
	Reserved2                                uint16 `json:"reserved_2"`
	GuardRFVerifyStackPointerFunctionPointer uint32 `json:"guard_rf_verify_stack_pointer_function_pointer"`
	HotPatchTableOffset                      uint32 `json:"hot_patch_table_offset"`
	Reserved3                                uint32 `json:"reserved_3"`
	EnclaveConfigurationPointer              uint32 `json:"enclave_configuration_pointer"`
	VolatileMetadataPointer                  uint32 `json:"volatile_metadata_pointer"`
	GuardEHContinuationTable                 uint32 `json:"guard_eh_continuation_table"`
	GuardEHContinuationCount                 uint32 `json:"guard_eh_continuation_count"`
	GuardXFGCheckFunctionPointer             uint32 `json:"guard_xfg_check_function_pointer"`
	GuardXFGDispatchFunctionPointer          uint32 `json:"guard_xfg_dispatch_function_pointer"`
	GuardXFGTableDispatchFunctionPointer     uint32 `json:"guard_xfg_table_dispatch_function_pointer"`
	CastGuardOSDeterminedFailureMode         uint32 `json:"cast_guard_os_determined_failure_mode"`
	GuardMemcpyFunctionPointer               uint32 `json:"guard_memcpy_function_pointer"`
}

// ImageLoadConfigDirectory64 Contains the load configuration data of an image for x64 binaries.
type ImageLoadConfigDirectory64 struct {
	// The actual size of the structure inclusive. May differ from the size
	// given in the data directory for Windows XP and earlier compatibility.
	Size uint32 `json:"size"`

	// Date and time stamp value.
	TimeDateStamp uint32 `json:"time_date_stamp"`

	// Major version number.
	MajorVersion uint16 `json:"major_version"`

	// Minor version number.
	MinorVersion uint16 `json:"minor_version"`

	// The global loader flags to clear for this process as the loader starts
	// the process.
	GlobalFlagsClear uint32 `json:"global_flags_clear"`

	// The global loader flags to set for this process as the loader starts the
	// process.
	GlobalFlagsSet uint32 `json:"global_flags_set"`

	// The default timeout value to use for this process's critical sections
	// that are abandoned.
	CriticalSectionDefaultTimeout uint32 `json:"critical_section_default_timeout"`

	// Memory that must be freed before it is returned to the system, in bytes.
	DeCommitFreeBlockThreshold uint64 `json:"de_commit_free_block_threshold"`

	// Total amount of free memory, in bytes.
	DeCommitTotalFreeThreshold uint64 `json:"de_commit_total_free_threshold"`

	// [x86 only] The VA of a list of addresses where the LOCK prefix is used so
	// that they can be replaced with NOP on single processor machines.
	LockPrefixTable uint64 `json:"lock_prefix_table"`

	// Maximum allocation size, in bytes.
	MaximumAllocationSize uint64 `json:"maximum_allocation_size"`

	// Maximum virtual memory size, in bytes.
	VirtualMemoryThreshold uint64 `json:"virtual_memory_threshold"`

	// Setting this field to a non-zero value is equivalent to calling
	// SetProcessAffinityMask with this value during process startup (.exe only)
	ProcessAffinityMask uint64 `json:"process_affinity_mask"`

	// Process heap flags that correspond to the first argument of the HeapCreate
	// function. These flags apply to the process heap that is created during
	// process startup.
	ProcessHeapFlags uint32 `json:"process_heap_flags"`

	// The service pack version identifier.
	CSDVersion uint16 `json:"csd_version"`

	// Must be zero.
	DependentLoadFlags uint16 `json:"dependent_load_flags"`

	// Reserved for use by the system.
	EditList uint64 `json:"edit_list"`

	// A pointer to a cookie that is used by Visual C++ or GS implementation.
	SecurityCookie uint64 `json:"security_cookie"`

	// [x86 only] The VA of the sorted table of RVAs of each valid, unique SE
	// handler in the image.
	SEHandlerTable uint64 `json:"se_handler_table"`

	// [x86 only] The count of unique handlers in the table.
	SEHandlerCount uint64 `json:"se_handler_count"`

	// The VA where Control Flow Guard check-function pointer is stored.
	GuardCFCheckFunctionPointer uint64 `json:"guard_cf_check_function_pointer"`

	// The VA where Control Flow Guard dispatch-function pointer is stored.
	GuardCFDispatchFunctionPointer uint64 `json:"guard_cf_dispatch_function_pointer"`

	// The VA of the sorted table of RVAs of each Control Flow Guard function in
	// the image.
	GuardCFFunctionTable uint64 `json:"guard_cf_function_table"`

	// The count of unique RVAs in the above table.
	GuardCFFunctionCount uint64 `json:"guard_cf_function_count"`

	// Control Flow Guard related flags.
	GuardFlags uint32 `json:"guard_flags"`

	// Code integrity information.
	CodeIntegrity ImageLoadConfigCodeIntegrity `json:"code_integrity"`

	// The VA where Control Flow Guard address taken IAT table is stored.
	GuardAddressTakenIATEntryTable uint64 `json:"guard_address_taken_iat_entry_table"`

	// The count of unique RVAs in the above table.
	GuardAddressTakenIATEntryCount uint64 `json:"guard_address_taken_iat_entry_count"`

	// The VA where Control Flow Guard long jump target table is stored.
	GuardLongJumpTargetTable uint64 `json:"guard_long_jump_target_table"`

	// The count of unique RVAs in the above table.
	GuardLongJumpTargetCount uint64 `json:"guard_long_jump_target_count"`

	DynamicValueRelocTable uint64 `json:"dynamic_value_reloc_table"`

	// Not sure when this was renamed from HybridMetadataPointer.
	CHPEMetadataPointer uint64 `json:"chpe_metadata_pointer"`

	GuardRFFailureRoutine                    uint64 `json:"guard_rf_failure_routine"`
	GuardRFFailureRoutineFunctionPointer     uint64 `json:"guard_rf_failure_routine_function_pointer"`
	DynamicValueRelocTableOffset             uint32 `json:"dynamic_value_reloc_table_offset"`
	DynamicValueRelocTableSection            uint16 `json:"dynamic_value_reloc_table_section"`
	Reserved2                                uint16 `json:"reserved_2"`
	GuardRFVerifyStackPointerFunctionPointer uint64 `json:"guard_rf_verify_stack_pointer_function_pointer"`
	HotPatchTableOffset                      uint32 `json:"hot_patch_table_offset"`
	Reserved3                                uint32 `json:"reserved_3"`
	EnclaveConfigurationPointer              uint64 `json:"enclave_configuration_pointer"`
	VolatileMetadataPointer                  uint64 `json:"volatile_metadata_pointer"`
	GuardEHContinuationTable                 uint64 `json:"guard_eh_continuation_table"`
	GuardEHContinuationCount                 uint64 `json:"guard_eh_continuation_count"`
	GuardXFGCheckFunctionPointer             uint64 `json:"guard_xfg_check_function_pointer"`
	GuardXFGDispatchFunctionPointer          uint64 `json:"guard_xfg_dispatch_function_pointer"`
	GuardXFGTableDispatchFunctionPointer     uint64 `json:"guard_xfg_table_dispatch_function_pointer"`
	CastGuardOSDeterminedFailureMode         uint64 `json:"cast_guard_os_determined_failure_mode"`
	GuardMemcpyFunctionPointer               uint64 `json:"guard_memcpy_function_pointer"`
}

// ImageCHPEMetadataX86 represents the X86_IMAGE_CHPE_METADATA_X86.
type ImageCHPEMetadataX86 struct {
	Version                                  uint32 `json:"version"`
	CHPECodeAddressRangeOffset               uint32 `json:"chpe_code_address_range_offset"`
	CHPECodeAddressRangeCount                uint32 `json:"chpe_code_address_range_count"`
	WoWA64ExceptionHandlerFunctionPtr        uint32 `json:"wow_a64_exception_handler_function_ptr"`
	WoWA64DispatchCallFunctionPtr            uint32 `json:"wow_a64_dispatch_call_function_ptr"`
	WoWA64DispatchIndirectCallFunctionPtr    uint32 `json:"wow_a64_dispatch_indirect_call_function_ptr"`
	WoWA64DispatchIndirectCallCfgFunctionPtr uint32 `json:"wow_a64_dispatch_indirect_call_cfg_function_ptr"`
	WoWA64DispatchRetFunctionPtr             uint32 `json:"wow_a64_dispatch_ret_function_ptr"`
	WoWA64DispatchRetLeafFunctionPtr         uint32 `json:"wow_a64_dispatch_ret_leaf_function_ptr"`
	WoWA64DispatchJumpFunctionPtr            uint32 `json:"wow_a64_dispatch_jump_function_ptr"`
	CompilerIATPointer                       uint32 `json:"compiler_iat_pointer"`       // Present if Version >= 2
	WoWA64RDTSCFunctionPtr                   uint32 `json:"wow_a64_rdtsc_function_ptr"` // Present if Version >= 3
}

type CodeRange struct {
	Begin   uint32 `json:"begin"`
	Length  uint32 `json:"length"`
	Machine uint8  `json:"machine"`
}

type CompilerIAT struct {
	RVA         uint32 `json:"rva"`
	Value       uint32 `json:"value"`
	Description string `json:"description"`
}

type HybridPE struct {
	CHPEMetadata interface{}   `json:"chpe_metadata"`
	CodeRanges   []CodeRange   `json:"code_ranges"`
	CompilerIAT  []CompilerIAT `json:"compiler_iat"`
}

// ImageDynamicRelocationTable represents the DVRT header.
type ImageDynamicRelocationTable struct {
	// Until now, there is only one version of the DVRT header (1)..
	Version uint32 `json:"version"`
	// Size represents the number of bytes after the header that contains
	// retpoline information.
	Size uint32 `json:"size"`
	//  IMAGE_DYNAMIC_RELOCATION DynamicRelocations[0];
}

// Dynamic value relocation entries following IMAGE_DYNAMIC_RELOCATION_TABLE.
// Each block starts with the header.

// ImageDynamicRelocation32 represents the 32-bit version of a reloc entry.
type ImageDynamicRelocation32 struct {
	// Symbol field identifies one of the existing types of dynamic relocations
	// so far (values 3, 4 and 5).
	Symbol uint32 `json:"symbol"`

	// Then, for each page, there is a block that starts with a relocation entry.
	// BaseRelocSize represents the size of the block.
	BaseRelocSize uint32 `json:"base_reloc_size"`
	//  IMAGE_BASE_RELOCATION BaseRelocations[0];
}

// ImageDynamicRelocation64 represents the 64-bit version of a reloc entry.
type ImageDynamicRelocation64 struct {
	// Symbol field identifies one of the existing types of dynamic relocations
	// so far (values 3, 4 and 5).
	Symbol uint64 `json:"symbol"`

	// Then, for each page, there is a block that starts with a relocation entry.
	// BaseRelocSize represents the size of the block.
	BaseRelocSize uint32 `json:"base_reloc_size"`
	//  IMAGE_BASE_RELOCATION BaseRelocations[0];
}

type ImageDynamicRelocation32v2 struct {
	HeaderSize    uint32 `json:"header_size"`
	FixupInfoSize uint32 `json:"fixup_info_size"`
	Symbol        uint32 `json:"symbol"`
	SymbolGroup   uint32 `json:"symbol_group"`
	Flags         uint32 `json:"flags"`
	// ...     variable length header fields
	// UCHAR   FixupInfo[FixupInfoSize]
}

type ImageDynamicRelocation64v2 struct {
	HeaderSize    uint32 `json:"header_size"`
	FixupInfoSize uint32 `json:"fixup_info_size"`
	Symbol        uint64 `json:"symbol"`
	SymbolGroup   uint32 `json:"symbol_group"`
	Flags         uint32 `json:"flags"`
	// ...     variable length header fields
	// UCHAR   FixupInfo[FixupInfoSize]
}

type ImagePrologueDynamicRelocationHeader struct {
	PrologueByteCount uint8 `json:"prologue_byte_count"`
	// UCHAR   PrologueBytes[PrologueByteCount];
}

type ImageEpilogueDynamicRelocationHeader struct {
	EpilogueCount               uint32 `json:"epilogue_count"`
	EpilogueByteCount           uint8  `json:"epilogue_byte_count"`
	BranchDescriptorElementSize uint8  `json:"branch_descriptor_element_size"`
	BranchDescriptorCount       uint8  `json:"branch_descriptor_count"`
	// UCHAR   BranchDescriptors[...];
	// UCHAR   BranchDescriptorBitMap[...];
}

type CFGFunction struct {
	// RVA of the target CFG call.
	RVA uint32 `json:"rva"`

	// Flags attached to each GFIDS entry if any call targets have metadata.
	Flags       ImageGuardFlagType `json:"flags"`
	Description string             `json:"description"`
}

type CFGIATEntry struct {
	RVA         uint32 `json:"rva"`
	IATValue    uint32 `json:"iat_value"`
	INTValue    uint32 `json:"int_value"`
	Description string `json:"description"`
}

type RelocBlock struct {
	ImgBaseReloc ImageBaseRelocation `json:"img_base_reloc"`
	TypeOffsets  []interface{}       `json:"type_offsets"`
}
type RelocEntry struct {
	// Could be ImageDynamicRelocation32{} or ImageDynamicRelocation64{}
	ImageDynamicRelocation interface{}  `json:"image_dynamic_relocation"`
	RelocBlocks            []RelocBlock `json:"reloc_blocks"`
}

// ImageImportControlTransferDynamicRelocation represents the Imported Address
// Retpoline (type 3), size = 4 bytes.
type ImageImportControlTransferDynamicRelocation struct {
	PageRelativeOffset uint16 `json:"page_relative_offset"` // (12 bits)
	// 1 - the opcode is a CALL
	// 0 - the opcode is a JMP.
	IndirectCall uint16 `json:"indirect_call"` // (1 bit)
	IATIndex     uint32 `json:"iat_index"`     // (19 bits)
}

// ImageIndirectControlTransferDynamicRelocation represents the Indirect Branch
// Retpoline (type 4), size = 2 bytes.
type ImageIndirectControlTransferDynamicRelocation struct {
	PageRelativeOffset uint16 `json:"page_relative_offset"` // (12 bits)
	IndirectCall       uint8  `json:"indirect_call"`        // (1 bit)
	RexWPrefix         uint8  `json:"rex_w_prefix"`         // (1 bit)
	CfgCheck           uint8  `json:"cfg_check"`            // (1 bit)
	Reserved           uint8  `json:"reserved"`             // (1 bit)
}

// ImageSwitchableBranchDynamicRelocation represents the Switchable Retpoline
// (type 5), size = 2 bytes.
type ImageSwitchableBranchDynamicRelocation struct {
	PageRelativeOffset uint16 `json:"page_relative_offset"` // (12 bits)
	RegisterNumber     uint16 `json:"register_number"`      // (4 bits)
}

// DVRT represents the Dynamic Value Relocation Table.
// The DVRT was originally introduced back in the Windows 10 Creators Update to
// improve kernel address space layout randomization (KASLR). It allowed the
// memory manager’s page frame number (PFN) database and page table self-map to
// be assigned dynamic addresses at runtime. The DVRT is stored directly in the
// binary and contains a series of relocation entries for each symbol (i.e.
// address) that is to be relocated. The relocation entries are themselves
// arranged in a hierarchical fashion grouped first by symbol and then by
// containing page to allow for a compact description of all locations in the
// binary that reference a relocatable symbol.
// Reference: https://techcommunity.microsoft.com/t5/windows-os-platform-blog/mitigating-spectre-variant-2-with-retpoline-on-windows/ba-p/295618
type DVRT struct {
	ImageDynamicRelocationTable `json:"image_dynamic_relocation_table"`
	Entries                     []RelocEntry `json:"entries"`
}

type Enclave struct {

	// Points to either ImageEnclaveConfig32{} or ImageEnclaveConfig64{}.
	Config interface{} `json:"config"`

	Imports []ImageEnclaveImport `json:"imports"`
}

type RangeTableEntry struct {
	RVA  uint32 `json:"rva"`
	Size uint32 `json:"size"`
}

type VolatileMetadata struct {
	Struct         ImageVolatileMetadata `json:"struct"`
	AccessRVATable []uint32              `json:"access_rva_table"`
	InfoRangeTable []RangeTableEntry     `json:"info_range_table"`
}
type LoadConfig struct {
	Struct           interface{}       `json:"struct"`
	SEH              []uint32          `json:"seh"`
	GFIDS            []CFGFunction     `json:"gfids"`
	CFGIAT           []CFGIATEntry     `json:"cfgiat"`
	CFGLongJump      []uint32          `json:"cfg_long_jump"`
	CHPE             *HybridPE         `json:"chpe"`
	DVRT             *DVRT             `json:"dvrt"`
	Enclave          *Enclave          `json:"enclave"`
	VolatileMetadata *VolatileMetadata `json:"volatile_metadata"`
}

// ImageLoadConfigCodeIntegrity Code Integrity in load config (CI).
type ImageLoadConfigCodeIntegrity struct {
	// Flags to indicate if CI information is available, etc.
	Flags uint16 `json:"flags"`
	// 0xFFFF means not available
	Catalog       uint16 `json:"catalog"`
	CatalogOffset uint32 `json:"catalog_offset"`
	// Additional bitmask to be defined later
	Reserved uint32 `json:"reserved"`
}

type ImageEnclaveConfig32 struct {

	// The size of the IMAGE_ENCLAVE_CONFIG32 structure, in bytes.
	Size uint32 `json:"size"`

	// The minimum size of the IMAGE_ENCLAVE_CONFIG32 structure that the image
	// loader must be able to process in order for the enclave to be usable.
	// This member allows an enclave to inform an earlier version of the image
	// loader that the image loader can safely load the enclave and ignore optional
	// members added to IMAGE_ENCLAVE_CONFIG32 for later versions of the enclave.

	// If the size of IMAGE_ENCLAVE_CONFIG32 that the image loader can process is
	// less than MinimumRequiredConfigSize, the enclave cannot be run securely.
	// If MinimumRequiredConfigSize is zero, the minimum size of the
	// IMAGE_ENCLAVE_CONFIG32 structure that the image loader must be able to
	// process in order for the enclave to be usable is assumed to be the size
	// of the structure through and including the MinimumRequiredConfigSize member.
	MinimumRequiredConfigSize uint32 `json:"minimum_required_config_size"`

	// A flag that indicates whether the enclave permits debugging.
	PolicyFlags uint32 `json:"policy_flags"`

	// The number of images in the array of images that the ImportList member
	// points to.
	NumberOfImports uint32 `json:"number_of_imports"`

	// The relative virtual address of the array of images that the enclave
	// image may import, with identity information for each image.
	ImportList uint32 `json:"import_list"`

	// The size of each image in the array of images that the ImportList member
	// points to.
	ImportEntrySize uint32 `json:"import_entry_size"`

	// The family identifier that the author of the enclave assigned to the enclave.
	FamilyID [ImageEnclaveShortIDLength]uint8 `json:"family_id"`

	// The image identifier that the author of the enclave assigned to the enclave.
	ImageID [ImageEnclaveShortIDLength]uint8 `json:"image_id"`

	// The version number that the author of the enclave assigned to the enclave.
	ImageVersion uint32 `json:"image_version"`

	// The security version number that the author of the enclave assigned to
	// the enclave.
	SecurityVersion uint32 `json:"security_version"`

	// The expected virtual size of the private address range for the enclave,
	// in bytes.
	EnclaveSize uint32 `json:"enclave_size"`

	// The maximum number of threads that can be created within the enclave.
	NumberOfThreads uint32 `json:"number_of_threads"`

	// A flag that indicates whether the image is suitable for use as the
	// primary image in the enclave.
	EnclaveFlags uint32 `json:"enclave_flags"`
}

type ImageEnclaveConfig64 struct {

	// The size of the IMAGE_ENCLAVE_CONFIG32 structure, in bytes.
	Size uint32 `json:"size"`

	// The minimum size of the IMAGE_ENCLAVE_CONFIG32 structure that the image
	// loader must be able to process in order for the enclave to be usable.
	// This member allows an enclave to inform an earlier version of the image
	// loader that the image loader can safely load the enclave and ignore
	// optional members added to IMAGE_ENCLAVE_CONFIG32 for later versions of
	// the enclave.

	// If the size of IMAGE_ENCLAVE_CONFIG32 that the image loader can process
	// is less than MinimumRequiredConfigSize, the enclave cannot be run securely.
	// If MinimumRequiredConfigSize is zero, the minimum size of the
	// IMAGE_ENCLAVE_CONFIG32 structure that the image loader must be able to
	// process in order for the enclave to be usable is assumed to be the size
	// of the structure through and including the MinimumRequiredConfigSize member.
	MinimumRequiredConfigSize uint32 `json:"minimum_required_config_size"`

	// A flag that indicates whether the enclave permits debugging.
	PolicyFlags uint32 `json:"policy_flags"`

	// The number of images in the array of images that the ImportList member
	// points to.
	NumberOfImports uint32 `json:"number_of_imports"`

	// The relative virtual address of the array of images that the enclave
	// image may import, with identity information for each image.
	ImportList uint32 `json:"import_list"`

	// The size of each image in the array of images that the ImportList member
	// points to.
	ImportEntrySize uint32 `json:"import_entry_size"`

	// The family identifier that the author of the enclave assigned to the enclave.
	FamilyID [ImageEnclaveShortIDLength]uint8 `json:"family_id"`

	// The image identifier that the author of the enclave assigned to the enclave.
	ImageID [ImageEnclaveShortIDLength]uint8 `json:"image_id"`

	// The version number that the author of the enclave assigned to the enclave.
	ImageVersion uint32 `json:"image_version"`

	// The security version number that the author of the enclave assigned to the enclave.
	SecurityVersion uint32 `json:"security_version"`

	// The expected virtual size of the private address range for the enclave,in bytes.
	EnclaveSize uint64 `json:"enclave_size"`

	// The maximum number of threads that can be created within the enclave.
	NumberOfThreads uint32 `json:"number_of_threads"`

	// A flag that indicates whether the image is suitable for use as the primary
	// image in the enclave.
	EnclaveFlags uint32 `json:"enclave_flags"`
}

// ImageEnclaveImport defines a entry in the array of images that an enclave can import.
type ImageEnclaveImport struct {

	// The type of identifier of the image that must match the value in the import record.
	MatchType uint32 `json:"match_type"`

	// The minimum enclave security version that each image must have for the
	// image to be imported successfully. The image is rejected unless its
	// enclave security version is equal to or greater than the minimum value in
	// the import record. Set the value in the import record to zero to turn off
	// the security version check.
	MinimumSecurityVersion uint32 `json:"minimum_security_version"`

	// The unique identifier of the primary module for the enclave, if the
	// MatchType member is IMAGE_ENCLAVE_IMPORT_MATCH_UNIQUE_ID. Otherwise,
	// the author identifier of the primary module for the enclave..
	UniqueOrAuthorID [ImageEnclaveLongIDLength]uint8 `json:"unique_or_author_id"`

	// The family identifier of the primary module for the enclave.
	FamilyID [ImageEnclaveShortIDLength]uint8 `json:"family_id"`

	// The image identifier of the primary module for the enclave.
	ImageID [ImageEnclaveShortIDLength]uint8 `json:"image_id"`

	// The relative virtual address of a NULL-terminated string that contains
	// the same value found in the import directory for the image.
	ImportName uint32 `json:"import_name"`

	// Reserved.
	Reserved uint32 `json:"reserved"`
}

type ImageVolatileMetadata struct {
	Size                       uint32 `json:"size"`
	Version                    uint32 `json:"version"`
	VolatileAccessTable        uint32 `json:"volatile_access_table"`
	VolatileAccessTableSize    uint32 `json:"volatile_access_table_size"`
	VolatileInfoRangeTable     uint32 `json:"volatile_info_range_table"`
	VolatileInfoRangeTableSize uint32 `json:"volatile_info_range_table_size"`
}

// The load configuration structure (IMAGE_LOAD_CONFIG_DIRECTORY) was formerly
// used in very limited cases in the Windows NT operating system itself to
// describe various features too difficult or too large to describe in the file

// header or optional header of the image. Current versions of the Microsoft
// linker and Windows XP and later versions of Windows use a new version of this
// structure for 32-bit x86-based systems that include reserved SEH technology.
// The data directory entry for a pre-reserved SEH load configuration structure
// must specify a particular size of the load configuration structure because
// the operating system loader always expects it to be a certain value. In that
// regard, the size is really only a version check. For compatibility with
// Windows XP and earlier versions of Windows, the size must be 64 for x86 images.
func (pe *File) parseLoadConfigDirectory(rva, size uint32) error {

	// As the load config structure changes over time,
	// we first read it size to figure out which one we have to cast against.
	fileOffset := pe.GetOffsetFromRva(rva)
	structSize, err := pe.ReadUint32(fileOffset)
	if err != nil {
		return err
	}

	// Use this helper function to print struct size.
	// PrintLoadConfigStruct()
	var loadCfg interface{}

	// Boundary check
	totalSize := fileOffset + size

	// Integer overflow
	if (totalSize > fileOffset) != (size > 0) {
		return ErrOutsideBoundary
	}

	if fileOffset >= pe.size || totalSize > pe.size {
		return ErrOutsideBoundary
	}

	if pe.Is32 {
		loadCfg32 := ImageLoadConfigDirectory32{}
		imgLoadConfigDirectory := make([]byte, binary.Size(loadCfg32))
		copy(imgLoadConfigDirectory, pe.data[fileOffset:fileOffset+structSize])
		buf := bytes.NewReader(imgLoadConfigDirectory)
		err = binary.Read(buf, binary.LittleEndian, &loadCfg32)
		loadCfg = loadCfg32
	} else {
		loadCfg64 := ImageLoadConfigDirectory64{}
		imgLoadConfigDirectory := make([]byte, binary.Size(loadCfg64))
		copy(imgLoadConfigDirectory, pe.data[fileOffset:fileOffset+structSize])
		buf := bytes.NewReader(imgLoadConfigDirectory)
		err = binary.Read(buf, binary.LittleEndian, &loadCfg64)
		loadCfg = loadCfg64
	}

	if err != nil {
		return err
	}

	// Save the load config struct.
	pe.HasLoadCFG = true
	pe.LoadConfig.Struct = loadCfg

	// Retrieve SEH handlers if there are any..
	if pe.Is32 {
		handlers := pe.getSEHHandlers()
		pe.LoadConfig.SEH = handlers
	}

	// Retrieve Control Flow Guard Function Targets if there are any.
	pe.LoadConfig.GFIDS = pe.getControlFlowGuardFunctions()

	// Retrieve Control Flow Guard IAT entries if there are any.
	pe.LoadConfig.CFGIAT = pe.getControlFlowGuardIAT()

	// Retrieve Long jump target functions if there are any.
	pe.LoadConfig.CFGLongJump = pe.getLongJumpTargetTable()

	// Retrieve compiled hybrid PE metadata if there are any.
	pe.LoadConfig.CHPE = pe.getHybridPE()

	// Retrieve dynamic value relocation table if there are any.
	pe.LoadConfig.DVRT = pe.getDynamicValueRelocTable()

	// Retrieve enclave configuration if there are any.
	pe.LoadConfig.Enclave = pe.getEnclaveConfiguration()

	// Retrieve volatile metadata table if there are any.
	pe.LoadConfig.VolatileMetadata = pe.getVolatileMetadata()

	return nil
}

// StringifyGuardFlags returns list of strings which describes the GuardFlags.
func StringifyGuardFlags(flags uint32) []string {
	var values []string
	guardFlagMap := map[uint32]string{
		ImageGuardCfInstrumented:                 "Instrumented",
		ImageGuardCfWInstrumented:                "WriteInstrumented",
		ImageGuardCfFunctionTablePresent:         "TargetMetadata",
		ImageGuardSecurityCookieUnused:           "SecurityCookieUnused",
		ImageGuardProtectDelayLoadIAT:            "DelayLoadIAT",
		ImageGuardDelayLoadIATInItsOwnSection:    "DelayLoadIATInItsOwnSection",
		ImageGuardCfExportSuppressionInfoPresent: "ExportSuppressionInfoPresent",
		ImageGuardCfEnableExportSuppression:      "EnableExportSuppression",
		ImageGuardCfLongJumpTablePresent:         "LongJumpTablePresent",
	}

	for k, s := range guardFlagMap {
		if k&flags != 0 {
			values = append(values, s)
		}
	}
	return values
}

func (pe *File) getSEHHandlers() []uint32 {

	var handlers []uint32
	v := reflect.ValueOf(pe.LoadConfig.Struct)

	// SEHandlerCount is found in index 19 of the struct.
	SEHandlerCount := uint32(v.Field(19).Uint())
	if SEHandlerCount > 0 {
		SEHandlerTable := uint32(v.Field(18).Uint())
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
		rva := SEHandlerTable - imageBase
		for i := uint32(0); i < SEHandlerCount; i++ {
			offset := pe.GetOffsetFromRva(rva + i*4)
			handler, err := pe.ReadUint32(offset)
			if err != nil {
				return handlers
			}

			handlers = append(handlers, handler)
		}
	}

	return handlers
}

func (pe *File) getControlFlowGuardFunctions() []CFGFunction {

	v := reflect.ValueOf(pe.LoadConfig.Struct)
	var GFIDS []CFGFunction
	var err error

	// The GFIDS table is an array of 4 + n bytes, where n is given by :
	// ((GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
	// IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT).

	// This allows for extra metadata to be attached to CFG call targets in
	// the future. The only currently defined metadata is an optional 1-byte
	// extra flags field (“GFIDS flags”) that is attached to each GFIDS
	// entry if any call targets have metadata.
	GuardFlags := v.Field(24).Uint()
	n := (GuardFlags & ImageGuardCfFunctionTableSizeMask) >>
		ImageGuardCfFunctionTableSizeShift
	GuardCFFunctionCount := v.Field(23).Uint()
	if GuardCFFunctionCount > 0 {
		if pe.Is32 {
			GuardCFFunctionTable := uint32(v.Field(22).Uint())
			imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
			rva := GuardCFFunctionTable - imageBase
			offset := pe.GetOffsetFromRva(rva)
			for i := uint32(1); i <= uint32(GuardCFFunctionCount); i++ {
				cfgFunction := CFGFunction{}
				var cfgFlags uint8
				cfgFunction.RVA, err = pe.ReadUint32(offset)
				if err != nil {
					return GFIDS
				}
				if n > 0 {
					err = pe.structUnpack(&cfgFlags, offset+4, uint32(n))
					if err != nil {
						return GFIDS
					}
					cfgFunction.Flags = ImageGuardFlagType(cfgFlags)
					if cfgFlags == ImageGuardFlagFIDSuppressed ||
						cfgFlags == ImageGuardFlagExportSuppressed {
						exportName := pe.GetExportFunctionByRVA(cfgFunction.RVA)
						cfgFunction.Description = exportName.Name
					}
				}

				GFIDS = append(GFIDS, cfgFunction)
				offset += 4 + uint32(n)
			}
		} else {
			GuardCFFunctionTable := v.Field(22).Uint()
			imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
			rva := uint32(GuardCFFunctionTable - imageBase)
			offset := pe.GetOffsetFromRva(rva)
			for i := uint64(1); i <= GuardCFFunctionCount; i++ {
				var cfgFlags uint8
				cfgFunction := CFGFunction{}
				cfgFunction.RVA, err = pe.ReadUint32(offset)
				if err != nil {
					return GFIDS
				}
				if n > 0 {
					pe.structUnpack(&cfgFlags, offset+4, uint32(n))
					cfgFunction.Flags = ImageGuardFlagType(cfgFlags)
					if cfgFlags == ImageGuardFlagFIDSuppressed ||
						cfgFlags == ImageGuardFlagExportSuppressed {
						exportName := pe.GetExportFunctionByRVA(cfgFunction.RVA)
						cfgFunction.Description = exportName.Name
					}
				}

				GFIDS = append(GFIDS, cfgFunction)
				offset += 4 + uint32(n)
			}
		}
	}
	return GFIDS
}

func (pe *File) getControlFlowGuardIAT() []CFGIATEntry {

	v := reflect.ValueOf(pe.LoadConfig.Struct)
	var GFGIAT []CFGIATEntry
	var err error

	// GuardAddressTakenIatEntryCount is found in index 27 of the struct.
	// An image that supports CFG ES includes a GuardAddressTakenIatEntryTable
	// whose count is provided by the GuardAddressTakenIatEntryCount as part
	// of its load configuration directory. This table is structurally
	// formatted the same as the GFIDS table. It uses the same GuardFlags
	// IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK mechanism to encode extra
	// optional metadata bytes in the address taken IAT table, though all
	// metadata bytes must be zero for the address taken IAT table and are
	// reserved.
	GuardFlags := v.Field(24).Uint()
	n := (GuardFlags & ImageGuardCfFunctionTableSizeMask) >>
		ImageGuardCfFunctionTableSizeShift
	GuardAddressTakenIatEntryCount := v.Field(27).Uint()
	if GuardAddressTakenIatEntryCount > 0 {
		if pe.Is32 {
			GuardAddressTakenIatEntryTable := uint32(v.Field(26).Uint())
			imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
			rva := GuardAddressTakenIatEntryTable - imageBase
			offset := pe.GetOffsetFromRva(rva)
			for i := uint32(1); i <= uint32(GuardAddressTakenIatEntryCount); i++ {
				cfgIATEntry := CFGIATEntry{}
				cfgIATEntry.RVA, err = pe.ReadUint32(offset)
				if err != nil {
					return GFGIAT
				}
				imp, index := pe.GetImportEntryInfoByRVA(cfgIATEntry.RVA)
				if len(imp.Functions) != 0 {
					cfgIATEntry.INTValue = uint32(imp.Functions[index].OriginalThunkValue)
					cfgIATEntry.IATValue = uint32(imp.Functions[index].ThunkValue)
					cfgIATEntry.Description = imp.Name + "!" + imp.Functions[index].Name
				}
				GFGIAT = append(GFGIAT, cfgIATEntry)
				offset += 4 + uint32(n)
			}
		} else {
			GuardAddressTakenIatEntryTable := v.Field(26).Uint()
			imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
			rva := uint32(GuardAddressTakenIatEntryTable - imageBase)
			offset := pe.GetOffsetFromRva(rva)
			for i := uint64(1); i <= GuardAddressTakenIatEntryCount; i++ {
				cfgIATEntry := CFGIATEntry{}
				cfgIATEntry.RVA, err = pe.ReadUint32(offset)
				if err != nil {
					return GFGIAT
				}
				imp, index := pe.GetImportEntryInfoByRVA(cfgIATEntry.RVA)
				if len(imp.Functions) != 0 {
					cfgIATEntry.INTValue = uint32(imp.Functions[index].OriginalThunkValue)
					cfgIATEntry.IATValue = uint32(imp.Functions[index].ThunkValue)
					cfgIATEntry.Description = imp.Name + "!" + imp.Functions[index].Name
				}

				GFGIAT = append(GFGIAT, cfgIATEntry)
				offset += 4 + uint32(n)
			}
		}

	}
	return GFGIAT
}

func (pe *File) getLongJumpTargetTable() []uint32 {

	v := reflect.ValueOf(pe.LoadConfig.Struct)
	var longJumpTargets []uint32

	// The long jump table represents a sorted array of RVAs that are valid
	// long jump targets. If a long jump target module sets
	// IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT in its GuardFlags field, then
	// all long jump targets must be enumerated in the LongJumpTargetTable.
	GuardFlags := v.Field(24).Uint()
	n := (GuardFlags & ImageGuardCfFunctionTableSizeMask) >>
		ImageGuardCfFunctionTableSizeShift

	// GuardLongJumpTargetCount is found in index 29 of the struct.
	GuardLongJumpTargetCount := v.Field(29).Uint()
	if GuardLongJumpTargetCount > 0 {
		if pe.Is32 {
			GuardLongJumpTargetTable := uint32(v.Field(28).Uint())
			imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
			rva := GuardLongJumpTargetTable - imageBase
			offset := pe.GetOffsetFromRva(rva)
			for i := uint32(1); i <= uint32(GuardLongJumpTargetCount); i++ {
				target, err := pe.ReadUint32(offset)
				if err != nil {
					return longJumpTargets
				}
				longJumpTargets = append(longJumpTargets, target)
				offset += 4 + uint32(n)
			}
		} else {
			GuardLongJumpTargetTable := v.Field(28).Uint()
			imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
			rva := uint32(GuardLongJumpTargetTable - imageBase)
			offset := pe.GetOffsetFromRva(rva)
			for i := uint64(1); i <= GuardLongJumpTargetCount; i++ {
				target, err := pe.ReadUint32(offset)
				if err != nil {
					return longJumpTargets
				}
				longJumpTargets = append(longJumpTargets, target)
				offset += 4 + uint32(n)
			}
		}

	}
	return longJumpTargets
}

func (pe *File) getHybridPE() *HybridPE {
	v := reflect.ValueOf(pe.LoadConfig.Struct)

	// CHPEMetadataPointer is found in index 31 of the struct.
	CHPEMetadataPointer := v.Field(31).Uint()
	if CHPEMetadataPointer == 0 {
		return nil
	}
	var rva uint32
	if pe.Is32 {
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
		rva = uint32(CHPEMetadataPointer) - imageBase
	} else {
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
		rva = uint32(CHPEMetadataPointer - imageBase)
	}

	// As the image CHPE metadata structure changes over time,
	// we first read its version to figure out which one we have to
	// cast against.
	fileOffset := pe.GetOffsetFromRva(rva)
	version, err := pe.ReadUint32(fileOffset)
	if err != nil {
		return nil
	}

	structSize := uint32(0)
	imgCHPEMetaX86 := ImageCHPEMetadataX86{}

	switch version {
	case 0x1:
		structSize = uint32(binary.Size(imgCHPEMetaX86) - 8)
	case 0x2:
		structSize = uint32(binary.Size(imgCHPEMetaX86) - 4)
	case 0x3:
		structSize = uint32(binary.Size(imgCHPEMetaX86))
	default:
		// This should be a newer version, default to the latest CHPE version.
		structSize = uint32(binary.Size(imgCHPEMetaX86))
	}

	// Boundary check
	totalSize := fileOffset + structSize

	// Integer overflow
	if (totalSize > fileOffset) != (structSize > 0) {
		pe.logger.Debug("encountered an outside read boundary when reading CHPE structure")
		return nil
	}

	if fileOffset >= pe.size || totalSize > pe.size {
		pe.logger.Debug("encountered an outside read boundary when reading CHPE structure")
		return nil
	}

	imgCHPEMeta := make([]byte, binary.Size(imgCHPEMetaX86))
	copy(imgCHPEMeta, pe.data[fileOffset:fileOffset+structSize])
	buf := bytes.NewReader(imgCHPEMeta)
	err = binary.Read(buf, binary.LittleEndian, &imgCHPEMetaX86)
	if err != nil {
		pe.logger.Debug("encountered an error while unpacking image CHPE Meta")
		return nil
	}

	hybridPE := HybridPE{}
	hybridPE.CHPEMetadata = imgCHPEMetaX86

	// Code Ranges

	/*
		typedef struct _IMAGE_CHPE_RANGE_ENTRY {
			union {
				ULONG StartOffset;
				struct {
					ULONG NativeCode : 1;
					ULONG AddressBits : 31;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			ULONG Length;
		} IMAGE_CHPE_RANGE_ENTRY, *PIMAGE_CHPE_RANGE_ENTRY;
	*/

	rva = imgCHPEMetaX86.CHPECodeAddressRangeOffset
	for i := 0; i < int(imgCHPEMetaX86.CHPECodeAddressRangeCount); i++ {

		codeRange := CodeRange{}
		fileOffset := pe.GetOffsetFromRva(rva)
		begin, err := pe.ReadUint32(fileOffset)
		if err != nil {
			break
		}

		if begin&1 == 1 {
			codeRange.Machine = 1
			begin = uint32(int(begin) & ^1)
		}
		codeRange.Begin = begin

		fileOffset += 4
		size, err := pe.ReadUint32(fileOffset)
		if err != nil {
			break
		}
		codeRange.Length = size

		hybridPE.CodeRanges = append(hybridPE.CodeRanges, codeRange)
		rva += 8
	}

	// Compiler IAT
	if imgCHPEMetaX86.CompilerIATPointer != 0 {
		rva := imgCHPEMetaX86.CompilerIATPointer
		for i := 0; i < 1024; i++ {
			compilerIAT := CompilerIAT{}
			compilerIAT.RVA = rva
			fileOffset = pe.GetOffsetFromRva(rva)
			compilerIAT.Value, err = pe.ReadUint32(fileOffset)
			if err != nil {
				break
			}

			impFunc, _ := pe.GetImportEntryInfoByRVA(compilerIAT.RVA)
			compilerIAT.Description = impFunc.Name
			hybridPE.CompilerIAT = append(
				hybridPE.CompilerIAT, compilerIAT)
			rva += 4
		}
	}
	return &hybridPE
}

func (pe *File) getDynamicValueRelocTable() *DVRT {

	var structSize uint32
	var imgDynRelocSize uint32
	var retpolineType uint8
	dvrt := DVRT{}
	imgDynRelocTable := ImageDynamicRelocationTable{}

	v := reflect.ValueOf(pe.LoadConfig.Struct)
	DynamicValueRelocTableOffset := v.Field(34).Uint()
	DynamicValueRelocTableSection := v.Field(35).Uint()
	if DynamicValueRelocTableOffset == 0 || DynamicValueRelocTableSection == 0 {
		return nil
	}

	section := pe.getSectionByName(".reloc")
	if section == nil {
		return nil
	}

	// Get the dynamic value relocation table header.
	rva := section.VirtualAddress + uint32(DynamicValueRelocTableOffset)
	offset := pe.GetOffsetFromRva(rva)
	structSize = uint32(binary.Size(imgDynRelocTable))
	err := pe.structUnpack(&imgDynRelocTable, offset, structSize)
	if err != nil {
		return nil
	}

	dvrt.ImageDynamicRelocationTable = imgDynRelocTable
	offset += structSize

	// Get dynamic relocation entries according to version.
	switch imgDynRelocTable.Version {
	case 1:
		relocTableIt := uint32(0)
		baseBlockSize := uint32(0)

		// Iterate over our dynamic reloc table entries.
		for relocTableIt < imgDynRelocTable.Size {

			relocEntry := RelocEntry{}

			// Each block starts with the header.
			if pe.Is32 {
				imgDynReloc := ImageDynamicRelocation32{}
				imgDynRelocSize = uint32(binary.Size(imgDynReloc))
				err = pe.structUnpack(&imgDynReloc, offset, imgDynRelocSize)
				if err != nil {
					return nil
				}
				relocEntry.ImageDynamicRelocation = imgDynReloc
				baseBlockSize = imgDynReloc.BaseRelocSize
				retpolineType = uint8(imgDynReloc.Symbol)
			} else {
				imgDynReloc := ImageDynamicRelocation64{}
				imgDynRelocSize = uint32(binary.Size(imgDynReloc))
				err = pe.structUnpack(&imgDynReloc, offset, imgDynRelocSize)
				if err != nil {
					return nil
				}
				relocEntry.ImageDynamicRelocation = imgDynReloc
				baseBlockSize = imgDynReloc.BaseRelocSize
				retpolineType = uint8(imgDynReloc.Symbol)
			}
			offset += imgDynRelocSize
			relocTableIt += imgDynRelocSize

			// Then, for each page, there is a block that starts with a relocation entry:
			blockIt := uint32(0)
			for blockIt <= baseBlockSize-imgDynRelocSize {
				relocBlock := RelocBlock{}

				baseReloc := ImageBaseRelocation{}
				structSize = uint32(binary.Size(baseReloc))
				err = pe.structUnpack(&baseReloc, offset, structSize)
				if err != nil {
					return nil
				}

				relocBlock.ImgBaseReloc = baseReloc
				offset += structSize

				// After that there are entries for all of the places which need
				// to be overwritten by the retpoline jump. The structure used
				// for those entries depends on the type (symbol) that was used
				// above. There are three types of retpoline so far. Entry for
				//each of them will contain pageRelativeOffset. The kernel uses
				// that entry to apply the proper replacement under
				// virtualAddress + pageRelativeOffset address.
				branchIt := uint32(0)
				switch retpolineType {
				case 3:
					for branchIt < (baseReloc.SizeOfBlock-structSize)/4 {
						imgImpCtrlTransDynReloc := ImageImportControlTransferDynamicRelocation{}

						dword, err := pe.ReadUint32(offset)
						if err != nil {
							return nil
						}

						imgImpCtrlTransDynReloc.PageRelativeOffset = uint16(dword) & 0xfff
						imgImpCtrlTransDynReloc.IndirectCall = uint16(dword) & 0x1000 >> 12
						imgImpCtrlTransDynReloc.IATIndex = dword & 0xFFFFE000 >> 13

						offset += 4
						branchIt += 1
						relocBlock.TypeOffsets = append(relocBlock.TypeOffsets, imgImpCtrlTransDynReloc)
					}
				case 4:
					for branchIt < (baseReloc.SizeOfBlock-structSize)/2 {
						imgIndirCtrlTransDynReloc := ImageIndirectControlTransferDynamicRelocation{}

						word, err := pe.ReadUint16(offset)
						if err != nil {
							return nil
						}
						imgIndirCtrlTransDynReloc.PageRelativeOffset = word & 0xfff
						imgIndirCtrlTransDynReloc.IndirectCall = uint8(word & 0x1000 >> 12)
						imgIndirCtrlTransDynReloc.RexWPrefix = uint8(word & 0x2000 >> 13)
						imgIndirCtrlTransDynReloc.CfgCheck = uint8(word & 0x4000 >> 14)
						imgIndirCtrlTransDynReloc.Reserved = uint8(word & 0x8000 >> 15)

						branchIt += 1
						offset += 2

						// Padding might be added at the end of the block.
						if (ImageIndirectControlTransferDynamicRelocation{}) == imgIndirCtrlTransDynReloc {
							continue
						}
						relocBlock.TypeOffsets = append(relocBlock.TypeOffsets, imgIndirCtrlTransDynReloc)
					}
				case 5:
					for branchIt < (baseReloc.SizeOfBlock-structSize)/2 {
						imgSwitchBranchDynReloc := ImageSwitchableBranchDynamicRelocation{}

						word, err := pe.ReadUint16(offset)
						if err != nil {
							return nil
						}
						imgSwitchBranchDynReloc.PageRelativeOffset = word & 0xfff
						imgSwitchBranchDynReloc.RegisterNumber = word & 0xf000 >> 12

						offset += 2
						branchIt += 1

						// Padding might be added at the end of the block.
						if (ImageSwitchableBranchDynamicRelocation{}) == imgSwitchBranchDynReloc {
							continue
						}
						relocBlock.TypeOffsets = append(relocBlock.TypeOffsets, imgSwitchBranchDynReloc)
					}
				}

				blockIt += baseReloc.SizeOfBlock
				relocEntry.RelocBlocks = append(relocEntry.RelocBlocks, relocBlock)
			}

			dvrt.Entries = append(dvrt.Entries, relocEntry)
			relocTableIt += baseBlockSize
		}
	case 2:
		fmt.Print("Got version 2 !")
	}

	return &dvrt
}

func (pe *File) getEnclaveConfiguration() *Enclave {

	enclave := Enclave{}

	v := reflect.ValueOf(pe.LoadConfig.Struct)
	EnclaveConfigurationPointer := v.Field(40).Uint()
	if EnclaveConfigurationPointer == 0 {
		return nil
	}

	if pe.Is32 {
		imgEnclaveCfg := ImageEnclaveConfig32{}
		imgEnclaveCfgSize := uint32(binary.Size(imgEnclaveCfg))
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
		rva := uint32(EnclaveConfigurationPointer) - imageBase
		offset := pe.GetOffsetFromRva(rva)
		err := pe.structUnpack(&imgEnclaveCfg, offset, imgEnclaveCfgSize)
		if err != nil {
			return nil
		}
		enclave.Config = imgEnclaveCfg
	} else {
		imgEnclaveCfg := ImageEnclaveConfig64{}
		imgEnclaveCfgSize := uint32(binary.Size(imgEnclaveCfg))
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
		rva := uint32(EnclaveConfigurationPointer - imageBase)
		offset := pe.GetOffsetFromRva(rva)
		err := pe.structUnpack(&imgEnclaveCfg, offset, imgEnclaveCfgSize)
		if err != nil {
			return nil
		}
		enclave.Config = imgEnclaveCfg
	}

	// Get the array of images that an enclave can import.
	val := reflect.ValueOf(enclave.Config)
	ImportListRVA := val.FieldByName("ImportList").Interface().(uint32)
	NumberOfImports := val.FieldByName("NumberOfImports").Interface().(uint32)
	ImportEntrySize := val.FieldByName("ImportEntrySize").Interface().(uint32)

	offset := pe.GetOffsetFromRva(ImportListRVA)
	for i := uint32(0); i < NumberOfImports; i++ {
		imgEncImp := ImageEnclaveImport{}
		imgEncImpSize := uint32(binary.Size(imgEncImp))
		err := pe.structUnpack(&imgEncImp, offset, imgEncImpSize)
		if err != nil {
			return nil
		}

		offset += ImportEntrySize
		enclave.Imports = append(enclave.Imports, imgEncImp)
	}

	return &enclave
}

func (pe *File) getVolatileMetadata() *VolatileMetadata {

	volatileMeta := VolatileMetadata{}
	imgVolatileMeta := ImageVolatileMetadata{}
	rva := uint32(0)

	v := reflect.ValueOf(pe.LoadConfig.Struct)
	if v.NumField() <= 41 {
		return nil
	}

	VolatileMetadataPointer := v.Field(41).Uint()
	if VolatileMetadataPointer == 0 {
		return nil
	}

	if pe.Is32 {
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
		rva = uint32(VolatileMetadataPointer) - imageBase
	} else {
		imageBase := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
		rva = uint32(VolatileMetadataPointer - imageBase)
	}

	offset := pe.GetOffsetFromRva(rva)
	imgVolatileMetaSize := uint32(binary.Size(imgVolatileMeta))
	err := pe.structUnpack(&imgVolatileMeta, offset, imgVolatileMetaSize)
	if err != nil {
		return nil
	}
	volatileMeta.Struct = imgVolatileMeta

	if imgVolatileMeta.VolatileAccessTable != 0 &&
		imgVolatileMeta.VolatileAccessTableSize != 0 {
		offset := pe.GetOffsetFromRva(imgVolatileMeta.VolatileAccessTable)
		for i := uint32(0); i < imgVolatileMeta.VolatileAccessTableSize/4; i++ {
			accessRVA, err := pe.ReadUint32(offset)
			if err != nil {
				break
			}

			volatileMeta.AccessRVATable = append(volatileMeta.AccessRVATable, accessRVA)
			offset += 4
		}
	}

	if imgVolatileMeta.VolatileInfoRangeTable != 0 && imgVolatileMeta.VolatileInfoRangeTableSize != 0 {
		offset := pe.GetOffsetFromRva(imgVolatileMeta.VolatileInfoRangeTable)
		rangeEntrySize := uint32(binary.Size(RangeTableEntry{}))
		for i := uint32(0); i < imgVolatileMeta.VolatileInfoRangeTableSize/rangeEntrySize; i++ {
			entry := RangeTableEntry{}
			err := pe.structUnpack(&entry, offset, rangeEntrySize)
			if err != nil {
				break
			}

			volatileMeta.InfoRangeTable = append(volatileMeta.InfoRangeTable, entry)
			offset += rangeEntrySize
		}
	}

	return &volatileMeta
}

// String returns a string interpretation of the load config directory image
// guard flag.
func (flag ImageGuardFlagType) String() string {
	imageGuardFlagTypeMap := map[ImageGuardFlagType]string{
		ImageGuardFlagFIDSuppressed:    "FID Suppressed",
		ImageGuardFlagExportSuppressed: "Export Suppressed",
	}

	v, ok := imageGuardFlagTypeMap[flag]
	if ok {
		return v
	}

	return "?"
}

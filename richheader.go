// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

const (
	// DansSignature ('DanS' as dword) is where the rich header struct starts.
	DansSignature = 0x536E6144

	// RichSignature ('0x68636952' as dword) is where the rich header struct ends.
	RichSignature = "Rich"

	// AnoDansSigNotFound is reported when rich header signature was found, but
	AnoDansSigNotFound = "Rich Header found, but could not locate DanS " +
		"signature"

	// AnoPaddingDwordNotZero is reported when rich header signature leading
	// padding DWORDs are not equal to 0.
	AnoPaddingDwordNotZero = "Rich header found: 3 leading padding DWORDs " +
		"not found after DanS signature"
)

// CompID represents the `@comp.id` structure.
type CompID struct {
	// The minor version information for the compiler used when building the product.
	MinorCV uint16 `json:"minor_compiler_version"`

	// Provides information about the identity or type of the objects used to
	// build the PE32.
	ProdID uint16 `json:"product_id"`

	// Indicates how often the object identified by the former two fields is
	// referenced by this PE32 file.
	Count uint32 `json:"count"`

	// The raw @comp.id structure (unmasked).
	Unmasked uint32 `json:"unmasked"`
}

// RichHeader is a structure that is written right after the MZ DOS header.
// It consists of pairs of 4-byte integers. And it is also
// encrypted using a simple XOR operation using the checksum as the key.
// The data between the magic values encodes the ‘bill of materials’ that were
// collected by the linker to produce the binary.
type RichHeader struct {
	XORKey     uint32   `json:"xor_key"`
	CompIDs    []CompID `json:"comp_ids"`
	DansOffset int      `json:"dans_offset"`
	Raw        []byte   `json:"raw"`
}

// ParseRichHeader parses the rich header struct.
func (pe *File) ParseRichHeader() error {

	rh := RichHeader{}
	ntHeaderOffset := pe.DOSHeader.AddressOfNewEXEHeader
	richSigOffset := bytes.Index(pe.data[:ntHeaderOffset], []byte(RichSignature))

	// For example, .NET executable files do not use the MSVC linker and these
	// executables do not contain a detectable Rich Header.
	if richSigOffset < 0 {
		return nil
	}

	// The DWORD following the "Rich" sequence is the XOR key stored by and
	// calculated by the linker. It is actually a checksum of the DOS header with
	// the e_lfanew zeroed out, and additionally includes the values of the
	// unencrypted "Rich" array. Using a checksum with encryption will not only
	// obfuscate the values, but it also serves as a rudimentary digital
	// signature. If the checksum is calculated from scratch once the values
	// have been decrypted, but doesn't match the stored key, it can be assumed
	// the structure had been tampered with. For those that go the extra step to
	// recalculate the checksum/key, this simple protection mechanism can be bypassed.
	rh.XORKey = binary.LittleEndian.Uint32(pe.data[richSigOffset+4:])

	// To decrypt the array, start with the DWORD just prior to the `Rich` sequence
	// and XOR it with the key. Continue the loop backwards, 4 bytes at a time,
	// until the sequence `DanS` is decrypted.
	var decRichHeader []uint32
	dansSigOffset := -1
	estimatedBeginDans := richSigOffset - 4 - binary.Size(ImageDOSHeader{})
	for it := 0; it < estimatedBeginDans; it += 4 {
		buff := binary.LittleEndian.Uint32(pe.data[richSigOffset-4-it:])
		res := buff ^ rh.XORKey
		if res == DansSignature {
			dansSigOffset = richSigOffset - it - 4
			break
		}

		decRichHeader = append(decRichHeader, res)
	}

	// Probe we successfuly found the `DanS` magic.
	if dansSigOffset == -1 {
		pe.Anomalies = append(pe.Anomalies, AnoDansSigNotFound)
		return nil
	}

	// Anomaly check: dansSigOffset is usually found in offset 0x80.
	if dansSigOffset != 0x80 {
		pe.Anomalies = append(pe.Anomalies, AnoDanSMagicOffset)
	}

	rh.DansOffset = dansSigOffset
	rh.Raw = pe.data[dansSigOffset : richSigOffset+8]

	// Reverse the decrypted rich header
	for i, j := 0, len(decRichHeader)-1; i < j; i, j = i+1, j-1 {
		decRichHeader[i], decRichHeader[j] = decRichHeader[j], decRichHeader[i]
	}

	// After the `DanS` signature, there are some zero-padded In practice,
	// Microsoft seems to have wanted the entries to begin on a 16-byte
	// (paragraph) boundary, so the 3 leading padding DWORDs can be safely
	// skipped as not belonging to the data.
	if decRichHeader[0] != 0 || decRichHeader[1] != 0 || decRichHeader[2] != 0 {
		pe.Anomalies = append(pe.Anomalies, AnoPaddingDwordNotZero)
	}

	// The array stores entries that are 8-bytes each, broken into 3 members.
	// Each entry represents either a tool that was employed as part of building
	// the executable or a statistic.
	// The @compid struct should be multiple of 8 (bytes), some malformed pe
	// files have incorrect number of entries.
	var lenCompIDs int
	if (len(decRichHeader)-3)%2 != 0 {
		lenCompIDs = len(decRichHeader) - 1
	} else {
		lenCompIDs = len(decRichHeader)
	}

	for i := 3; i < lenCompIDs; i += 2 {
		cid := CompID{}
		compid := make([]byte, binary.Size(cid))
		binary.LittleEndian.PutUint32(compid, decRichHeader[i])
		binary.LittleEndian.PutUint32(compid[4:], decRichHeader[i+1])
		buf := bytes.NewReader(compid)
		err := binary.Read(buf, binary.LittleEndian, &cid)
		if err != nil {
			return err
		}
		cid.Unmasked = binary.LittleEndian.Uint32(compid)
		rh.CompIDs = append(rh.CompIDs, cid)
	}

	pe.RichHeader = rh
	pe.HasRichHdr = true

	checksum := pe.RichHeaderChecksum()
	if checksum != rh.XORKey {
		pe.Anomalies = append(pe.Anomalies, "Invalid rich header checksum")
	}

	return nil
}

// RichHeaderChecksum calculate the Rich Header checksum.
func (pe *File) RichHeaderChecksum() uint32 {

	checksum := uint32(pe.RichHeader.DansOffset)

	// First, calculate the sum of the DOS header bytes each rotated left the
	// number of times their position relative to the start of the DOS header e.g.
	// second byte is rotated left 2x using rol operation.
	for i := 0; i < pe.RichHeader.DansOffset; i++ {
		// skip over dos e_lfanew field at offset 0x3C
		if i >= 0x3C && i < 0x40 {
			continue
		}
		b := uint32(pe.data[i])
		checksum += ((b << (i % 32)) | (b>>(32-(i%32)))&0xff)
		checksum &= 0xFFFFFFFF
	}

	// Next, take summation of each Rich header entry by combining its ProductId
	// and BuildNumber into a single 32 bit number and rotating by its count.
	for _, compid := range pe.RichHeader.CompIDs {
		checksum += (compid.Unmasked<<(compid.Count%32) |
			compid.Unmasked>>(32-(compid.Count%32)))
		checksum &= 0xFFFFFFFF
	}

	return checksum
}

// RichHeaderHash calculate the Rich Header hash.
func (pe *File) RichHeaderHash() string {
	if !pe.HasRichHdr {
		return ""
	}

	richIndex := bytes.Index(pe.RichHeader.Raw, []byte(RichSignature))
	if richIndex == -1 {
		return ""
	}

	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, pe.RichHeader.XORKey)

	rawData := pe.RichHeader.Raw[:richIndex]
	clearData := make([]byte, len(rawData))
	for idx, val := range rawData {
		clearData[idx] = val ^ key[idx%len(key)]
	}
	return fmt.Sprintf("%x", md5.Sum(clearData))
}

// ProdIDtoStr maps product ids to MS internal names.
// list from: https://github.com/kirschju/richheader
func ProdIDtoStr(prodID uint16) string {

	prodIDtoStrMap := map[uint16]string{
		0x0000: "Unknown",
		0x0001: "Import0",
		0x0002: "Linker510",
		0x0003: "Cvtomf510",
		0x0004: "Linker600",
		0x0005: "Cvtomf600",
		0x0006: "Cvtres500",
		0x0007: "Utc11_Basic",
		0x0008: "Utc11_C",
		0x0009: "Utc12_Basic",
		0x000a: "Utc12_C",
		0x000b: "Utc12_CPP",
		0x000c: "AliasObj60",
		0x000d: "VisualBasic60",
		0x000e: "Masm613",
		0x000f: "Masm710",
		0x0010: "Linker511",
		0x0011: "Cvtomf511",
		0x0012: "Masm614",
		0x0013: "Linker512",
		0x0014: "Cvtomf512",
		0x0015: "Utc12_C_Std",
		0x0016: "Utc12_CPP_Std",
		0x0017: "Utc12_C_Book",
		0x0018: "Utc12_CPP_Book",
		0x0019: "Implib700",
		0x001a: "Cvtomf700",
		0x001b: "Utc13_Basic",
		0x001c: "Utc13_C",
		0x001d: "Utc13_CPP",
		0x001e: "Linker610",
		0x001f: "Cvtomf610",
		0x0020: "Linker601",
		0x0021: "Cvtomf601",
		0x0022: "Utc12_1_Basic",
		0x0023: "Utc12_1_C",
		0x0024: "Utc12_1_CPP",
		0x0025: "Linker620",
		0x0026: "Cvtomf620",
		0x0027: "AliasObj70",
		0x0028: "Linker621",
		0x0029: "Cvtomf621",
		0x002a: "Masm615",
		0x002b: "Utc13_LTCG_C",
		0x002c: "Utc13_LTCG_CPP",
		0x002d: "Masm620",
		0x002e: "ILAsm100",
		0x002f: "Utc12_2_Basic",
		0x0030: "Utc12_2_C",
		0x0031: "Utc12_2_CPP",
		0x0032: "Utc12_2_C_Std",
		0x0033: "Utc12_2_CPP_Std",
		0x0034: "Utc12_2_C_Book",
		0x0035: "Utc12_2_CPP_Book",
		0x0036: "Implib622",
		0x0037: "Cvtomf622",
		0x0038: "Cvtres501",
		0x0039: "Utc13_C_Std",
		0x003a: "Utc13_CPP_Std",
		0x003b: "Cvtpgd1300",
		0x003c: "Linker622",
		0x003d: "Linker700",
		0x003e: "Export622",
		0x003f: "Export700",
		0x0040: "Masm700",
		0x0041: "Utc13_POGO_I_C",
		0x0042: "Utc13_POGO_I_CPP",
		0x0043: "Utc13_POGO_O_C",
		0x0044: "Utc13_POGO_O_CPP",
		0x0045: "Cvtres700",
		0x0046: "Cvtres710p",
		0x0047: "Linker710p",
		0x0048: "Cvtomf710p",
		0x0049: "Export710p",
		0x004a: "Implib710p",
		0x004b: "Masm710p",
		0x004c: "Utc1310p_C",
		0x004d: "Utc1310p_CPP",
		0x004e: "Utc1310p_C_Std",
		0x004f: "Utc1310p_CPP_Std",
		0x0050: "Utc1310p_LTCG_C",
		0x0051: "Utc1310p_LTCG_CPP",
		0x0052: "Utc1310p_POGO_I_C",
		0x0053: "Utc1310p_POGO_I_CPP",
		0x0054: "Utc1310p_POGO_O_C",
		0x0055: "Utc1310p_POGO_O_CPP",
		0x0056: "Linker624",
		0x0057: "Cvtomf624",
		0x0058: "Export624",
		0x0059: "Implib624",
		0x005a: "Linker710",
		0x005b: "Cvtomf710",
		0x005c: "Export710",
		0x005d: "Implib710",
		0x005e: "Cvtres710",
		0x005f: "Utc1310_C",
		0x0060: "Utc1310_CPP",
		0x0061: "Utc1310_C_Std",
		0x0062: "Utc1310_CPP_Std",
		0x0063: "Utc1310_LTCG_C",
		0x0064: "Utc1310_LTCG_CPP",
		0x0065: "Utc1310_POGO_I_C",
		0x0066: "Utc1310_POGO_I_CPP",
		0x0067: "Utc1310_POGO_O_C",
		0x0068: "Utc1310_POGO_O_CPP",
		0x0069: "AliasObj710",
		0x006a: "AliasObj710p",
		0x006b: "Cvtpgd1310",
		0x006c: "Cvtpgd1310p",
		0x006d: "Utc1400_C",
		0x006e: "Utc1400_CPP",
		0x006f: "Utc1400_C_Std",
		0x0070: "Utc1400_CPP_Std",
		0x0071: "Utc1400_LTCG_C",
		0x0072: "Utc1400_LTCG_CPP",
		0x0073: "Utc1400_POGO_I_C",
		0x0074: "Utc1400_POGO_I_CPP",
		0x0075: "Utc1400_POGO_O_C",
		0x0076: "Utc1400_POGO_O_CPP",
		0x0077: "Cvtpgd1400",
		0x0078: "Linker800",
		0x0079: "Cvtomf800",
		0x007a: "Export800",
		0x007b: "Implib800",
		0x007c: "Cvtres800",
		0x007d: "Masm800",
		0x007e: "AliasObj800",
		0x007f: "PhoenixPrerelease",
		0x0080: "Utc1400_CVTCIL_C",
		0x0081: "Utc1400_CVTCIL_CPP",
		0x0082: "Utc1400_LTCG_MSIL",
		0x0083: "Utc1500_C",
		0x0084: "Utc1500_CPP",
		0x0085: "Utc1500_C_Std",
		0x0086: "Utc1500_CPP_Std",
		0x0087: "Utc1500_CVTCIL_C",
		0x0088: "Utc1500_CVTCIL_CPP",
		0x0089: "Utc1500_LTCG_C",
		0x008a: "Utc1500_LTCG_CPP",
		0x008b: "Utc1500_LTCG_MSIL",
		0x008c: "Utc1500_POGO_I_C",
		0x008d: "Utc1500_POGO_I_CPP",
		0x008e: "Utc1500_POGO_O_C",
		0x008f: "Utc1500_POGO_O_CPP",
		0x0090: "Cvtpgd1500",
		0x0091: "Linker900",
		0x0092: "Export900",
		0x0093: "Implib900",
		0x0094: "Cvtres900",
		0x0095: "Masm900",
		0x0096: "AliasObj900",
		0x0097: "Resource",
		0x0098: "AliasObj1000",
		0x0099: "Cvtpgd1600",
		0x009a: "Cvtres1000",
		0x009b: "Export1000",
		0x009c: "Implib1000",
		0x009d: "Linker1000",
		0x009e: "Masm1000",
		0x009f: "Phx1600_C",
		0x00a0: "Phx1600_CPP",
		0x00a1: "Phx1600_CVTCIL_C",
		0x00a2: "Phx1600_CVTCIL_CPP",
		0x00a3: "Phx1600_LTCG_C",
		0x00a4: "Phx1600_LTCG_CPP",
		0x00a5: "Phx1600_LTCG_MSIL",
		0x00a6: "Phx1600_POGO_I_C",
		0x00a7: "Phx1600_POGO_I_CPP",
		0x00a8: "Phx1600_POGO_O_C",
		0x00a9: "Phx1600_POGO_O_CPP",
		0x00aa: "Utc1600_C",
		0x00ab: "Utc1600_CPP",
		0x00ac: "Utc1600_CVTCIL_C",
		0x00ad: "Utc1600_CVTCIL_CPP",
		0x00ae: "Utc1600_LTCG_C",
		0x00af: "Utc1600_LTCG_CPP",
		0x00b0: "Utc1600_LTCG_MSIL",
		0x00b1: "Utc1600_POGO_I_C",
		0x00b2: "Utc1600_POGO_I_CPP",
		0x00b3: "Utc1600_POGO_O_C",
		0x00b4: "Utc1600_POGO_O_CPP",
		0x00b5: "AliasObj1010",
		0x00b6: "Cvtpgd1610",
		0x00b7: "Cvtres1010",
		0x00b8: "Export1010",
		0x00b9: "Implib1010",
		0x00ba: "Linker1010",
		0x00bb: "Masm1010",
		0x00bc: "Utc1610_C",
		0x00bd: "Utc1610_CPP",
		0x00be: "Utc1610_CVTCIL_C",
		0x00bf: "Utc1610_CVTCIL_CPP",
		0x00c0: "Utc1610_LTCG_C",
		0x00c1: "Utc1610_LTCG_CPP",
		0x00c2: "Utc1610_LTCG_MSIL",
		0x00c3: "Utc1610_POGO_I_C",
		0x00c4: "Utc1610_POGO_I_CPP",
		0x00c5: "Utc1610_POGO_O_C",
		0x00c6: "Utc1610_POGO_O_CPP",
		0x00c7: "AliasObj1100",
		0x00c8: "Cvtpgd1700",
		0x00c9: "Cvtres1100",
		0x00ca: "Export1100",
		0x00cb: "Implib1100",
		0x00cc: "Linker1100",
		0x00cd: "Masm1100",
		0x00ce: "Utc1700_C",
		0x00cf: "Utc1700_CPP",
		0x00d0: "Utc1700_CVTCIL_C",
		0x00d1: "Utc1700_CVTCIL_CPP",
		0x00d2: "Utc1700_LTCG_C",
		0x00d3: "Utc1700_LTCG_CPP",
		0x00d4: "Utc1700_LTCG_MSIL",
		0x00d5: "Utc1700_POGO_I_C",
		0x00d6: "Utc1700_POGO_I_CPP",
		0x00d7: "Utc1700_POGO_O_C",
		0x00d8: "Utc1700_POGO_O_CPP",
		0x00d9: "AliasObj1200",
		0x00da: "Cvtpgd1800",
		0x00db: "Cvtres1200",
		0x00dc: "Export1200",
		0x00dd: "Implib1200",
		0x00de: "Linker1200",
		0x00df: "Masm1200",
		0x00e0: "Utc1800_C",
		0x00e1: "Utc1800_CPP",
		0x00e2: "Utc1800_CVTCIL_C",
		0x00e3: "Utc1800_CVTCIL_CPP",
		0x00e4: "Utc1800_LTCG_C",
		0x00e5: "Utc1800_LTCG_CPP",
		0x00e6: "Utc1800_LTCG_MSIL",
		0x00e7: "Utc1800_POGO_I_C",
		0x00e8: "Utc1800_POGO_I_CPP",
		0x00e9: "Utc1800_POGO_O_C",
		0x00ea: "Utc1800_POGO_O_CPP",
		0x00eb: "AliasObj1210",
		0x00ec: "Cvtpgd1810",
		0x00ed: "Cvtres1210",
		0x00ee: "Export1210",
		0x00ef: "Implib1210",
		0x00f0: "Linker1210",
		0x00f1: "Masm1210",
		0x00f2: "Utc1810_C",
		0x00f3: "Utc1810_CPP",
		0x00f4: "Utc1810_CVTCIL_C",
		0x00f5: "Utc1810_CVTCIL_CPP",
		0x00f6: "Utc1810_LTCG_C",
		0x00f7: "Utc1810_LTCG_CPP",
		0x00f8: "Utc1810_LTCG_MSIL",
		0x00f9: "Utc1810_POGO_I_C",
		0x00fa: "Utc1810_POGO_I_CPP",
		0x00fb: "Utc1810_POGO_O_C",
		0x00fc: "Utc1810_POGO_O_CPP",
		0x00fd: "AliasObj1400",
		0x00fe: "Cvtpgd1900",
		0x00ff: "Cvtres1400",
		0x0100: "Export1400",
		0x0101: "Implib1400",
		0x0102: "Linker1400",
		0x0103: "Masm1400",
		0x0104: "Utc1900_C",
		0x0105: "Utc1900_CPP",
		0x0106: "Utc1900_CVTCIL_C",
		0x0107: "Utc1900_CVTCIL_CPP",
		0x0108: "Utc1900_LTCG_C",
		0x0109: "Utc1900_LTCG_CPP",
		0x010a: "Utc1900_LTCG_MSIL",
		0x010b: "Utc1900_POGO_I_C",
		0x010c: "Utc1900_POGO_I_CPP",
		0x010d: "Utc1900_POGO_O_C",
		0x010e: "Utc1900_POGO_O_CPP",
	}

	if val, ok := prodIDtoStrMap[prodID]; ok {
		return val
	}

	return "?"
}

// ProdIDtoVSversion retrieves the Visual Studio version from product id.
// list from: https://github.com/kirschju/richheader
func ProdIDtoVSversion(prodID uint16) string {
	if prodID > 0x010e {
		return ""
	} else if prodID >= 0x00fd && prodID < 0x010e+1 {
		return "Visual Studio 2015 14.00"
	} else if prodID >= 0x00eb && prodID < 0x00fd {
		return "Visual Studio 2013 12.10"
	} else if prodID >= 0x00d9 && prodID < 0x00eb {
		return "Visual Studio 2013 12.00"
	} else if prodID >= 0x00c7 && prodID < 0x00d9 {
		return "Visual Studio 2012 11.00"
	} else if prodID >= 0x00b5 && prodID < 0x00c7 {
		return "Visual Studio 2010 10.10"
	} else if prodID >= 0x0098 && prodID < 0x00b5 {
		return "Visual Studio 2010 10.00"
	} else if prodID >= 0x0083 && prodID < 0x0098 {
		return "Visual Studio 2008 09.00"
	} else if prodID >= 0x006d && prodID < 0x0083 {
		return "Visual Studio 2005 08.00"
	} else if prodID >= 0x005a && prodID < 0x006d {
		return "Visual Studio 2003 07.10"
	} else if prodID == 1 {
		return "Visual Studio"
	} else {
		return "<unknown>"
	}
}

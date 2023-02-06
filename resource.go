// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

// ResourceType represents a resource type.
type ResourceType int

const (
	maxAllowedEntries = 0x1000
)

// Predefined Resource Types.
const (
	RTCursor       ResourceType = iota + 1      // Hardware-dependent cursor resource.
	RTBitmap                    = 2             // Bitmap resource.
	RTIcon                      = 3             // Hardware-dependent icon resource.
	RTMenu                      = 4             // Menu resource.
	RTDialog                    = 5             // Dialog box.
	RTString                    = 6             // String-table entry.
	RTFontDir                   = 7             // Font directory resource.
	RTFont                      = 8             // Font resource.
	RTAccelerator               = 9             // Accelerator table.
	RTRCdata                    = 10            // Application-defined resource (raw data).
	RTMessageTable              = 11            // Message-table entry.
	RTGroupCursor               = RTCursor + 11 // Hardware-independent cursor resource.
	RTGroupIcon                 = RTIcon + 11   // Hardware-independent icon resource.
	RTVersion                   = 16            // Version resource.
	RTDlgInclude                = 17            // Dialog include entry.
	RTPlugPlay                  = 19            // Plug and Play resource.
	RTVxD                       = 20            // VXD.
	RTAniCursor                 = 21            // Animated cursor.
	RTAniIcon                   = 22            // Animated icon.
	RTHtml                      = 23            // HTML resource.
	RTManifest                  = 24            // Side-by-Side Assembly Manifest.
)

// ImageResourceDirectory represents the IMAGE_RESOURCE_DIRECTORY.
// This data structure should be considered the heading of a table because the
// table actually consists of directory entries.
type ImageResourceDirectory struct {
	// Resource flags. This field is reserved for future use. It is currently
	// set to zero.
	Characteristics uint32 `json:"characteristics"`

	// The time that the resource data was created by the resource compiler.
	TimeDateStamp uint32 `json:"time_date_stamp"`

	// The major version number, set by the user.
	MajorVersion uint16 `json:"major_version"`

	// The minor version number, set by the user.
	MinorVersion uint16 `json:"minor_version"`

	// The number of directory entries immediately following the table that use
	// strings to identify Type, Name, or Language entries (depending on the
	// level of the table).
	NumberOfNamedEntries uint16 `json:"number_of_named_entries"`

	// The number of directory entries immediately following the Name entries
	// that use numeric IDs for Type, Name, or Language entries.
	NumberOfIDEntries uint16 `json:"number_of_id_entries"`
}

// ImageResourceDirectoryEntry represents an entry in the resource directory
// entries.
type ImageResourceDirectoryEntry struct {
	// Name is used to identify either a type of resource, a resource name, or a
	// resource's language ID.
	Name uint32 `json:"name"`

	// OffsetToData is always used to point to a sibling in the tree, either a
	// directory node or a leaf node.
	OffsetToData uint32 `json:"offset_to_data"`
}

// ImageResourceDataEntry Each Resource Data entry describes an actual unit of
// raw data in the Resource Data area.
type ImageResourceDataEntry struct {
	// The address of a unit of resource data in the Resource Data area.
	OffsetToData uint32 `json:"offset_to_data"`

	// The size, in bytes, of the resource data that is pointed to by the Data
	// RVA field.
	Size uint32 `json:"size"`

	// The code page that is used to decode code point values within the
	// resource data. Typically, the code page would be the Unicode code page.
	CodePage uint32 `json:"code_page"`

	// Reserved, must be 0.
	Reserved uint32 `json:"reserved"`
}

// ResourceDirectory represents resource directory information.
type ResourceDirectory struct {
	// IMAGE_RESOURCE_DIRECTORY structure.
	Struct ImageResourceDirectory `json:"struct"`

	// list of entries.
	Entries []ResourceDirectoryEntry `json:"entries"`
}

// ResourceDirectoryEntry represents a resource directory entry.
type ResourceDirectoryEntry struct {
	// IMAGE_RESOURCE_DIRECTORY_ENTRY structure.
	Struct ImageResourceDirectoryEntry `json:"struct"`

	// If the resource is identified by name this attribute will contain the
	// name string. Empty string otherwise. If identified by id, the id is
	// available at `ID` field.
	Name string `json:"name"`

	// The resource identifier.
	ID uint32 `json:"id"`

	// IsResourceDir tell us if the entry is pointing to a resource directory or
	// a resource data entry.
	IsResourceDir bool `json:"is_resource_dir"`

	// If this entry has a lower level directory this attribute will point to
	// the ResourceDirData instance representing it.
	Directory ResourceDirectory `json:"directory"`

	// If this entry has no further lower directories and points to the actual
	// resource data, this attribute will reference the corresponding
	// ResourceDataEntry instance.
	Data ResourceDataEntry `json:"data"`
}

// ResourceDataEntry represents a resource data entry.
type ResourceDataEntry struct {

	// IMAGE_RESOURCE_DATA_ENTRY structure.
	Struct ImageResourceDataEntry `json:"struct"`

	// Primary language ID.
	Lang ResourceLang `json:"lang"`

	// Sub language ID.
	SubLang ResourceSubLang `json:"sub_lang"`
}

func (pe *File) parseResourceDataEntry(rva uint32) ImageResourceDataEntry {
	dataEntry := ImageResourceDataEntry{}
	dataEntrySize := uint32(binary.Size(dataEntry))
	offset := pe.GetOffsetFromRva(rva)
	err := pe.structUnpack(&dataEntry, offset, dataEntrySize)
	if err != nil {
		pe.logger.Warnf("Error parsing a resource directory data entry, the RVA is invalid")
	}
	return dataEntry
}

func (pe *File) parseResourceDirectoryEntry(rva uint32) *ImageResourceDirectoryEntry {
	resource := ImageResourceDirectoryEntry{}
	resourceSize := uint32(binary.Size(resource))
	offset := pe.GetOffsetFromRva(rva)
	err := pe.structUnpack(&resource, offset, resourceSize)
	if err != nil {
		return nil
	}

	if resource == (ImageResourceDirectoryEntry{}) {
		return nil
	}

	// resource.NameOffset = resource.Name & 0x7FFFFFFF

	// resource.__pad = resource.Name & 0xFFFF0000
	// resource.Id = resource.Name & 0x0000FFFF

	// resource.DataIsDirectory = (resource.OffsetToData & 0x80000000) >> 31
	// resource.OffsetToDirectory = resource.OffsetToData & 0x7FFFFFFF

	return &resource
}

// Navigating the resource directory hierarchy is like navigating a hard disk.
// There's a master directory (the root directory), which has subdirectories.
// The subdirectories have subdirectories of their own that may point to the
// raw resource data for things like dialog templates.
func (pe *File) doParseResourceDirectory(rva, size, baseRVA, level uint32,
	dirs []uint32) (ResourceDirectory, error) {

	resourceDir := ImageResourceDirectory{}
	resourceDirSize := uint32(binary.Size(resourceDir))
	offset := pe.GetOffsetFromRva(rva)
	err := pe.structUnpack(&resourceDir, offset, resourceDirSize)
	if err != nil {
		return ResourceDirectory{}, err
	}

	if baseRVA == 0 {
		baseRVA = rva
	}

	if len(dirs) == 0 {
		dirs = append(dirs, rva)
	}

	// Advance the RVA to the position immediately following the directory
	// table header and pointing to the first entry in the table.
	rva += resourceDirSize

	numberOfEntries := int(resourceDir.NumberOfNamedEntries +
		resourceDir.NumberOfIDEntries)
	var dirEntries []ResourceDirectoryEntry

	// Set a hard limit on the maximum reasonable number of entries.
	if numberOfEntries > maxAllowedEntries {
		pe.logger.Warnf(`Error parsing the resources directory.
		 The directory contains %d entries`, numberOfEntries)
		return ResourceDirectory{}, nil
	}

	for i := 0; i < numberOfEntries; i++ {
		res := pe.parseResourceDirectoryEntry(rva)
		if res == nil {
			pe.logger.Warn("Error parsing a resource directory entry, the RVA is invalid")
			break
		}

		nameIsString := (res.Name & 0x80000000) >> 31
		entryName := ""
		entryID := uint32(0)
		if nameIsString == 0 {
			entryID = res.Name
		} else {
			nameOffset := res.Name & 0x7FFFFFFF
			uStringOffset := pe.GetOffsetFromRva(baseRVA + nameOffset)
			maxLen, err := pe.ReadUint16(uStringOffset)
			if err != nil {
				break
			}
			entryName = pe.readUnicodeStringAtRVA(baseRVA+nameOffset+2,
				uint32(maxLen*2))
		}

		// A directory entry points to either another resource directory or to
		// the data for an individual resource. When the directory entry points
		// to another resource directory, the high bit of the second DWORD in
		// the structure is set and the remaining 31 bits are an offset to the
		// resource directory.
		dataIsDirectory := (res.OffsetToData & 0x80000000) >> 31

		// The offset is relative to the beginning of the resource section,
		// not an RVA.
		OffsetToDirectory := res.OffsetToData & 0x7FFFFFFF
		if dataIsDirectory > 0 {
			// One trick malware can do is to recursively reference
			// the next directory. This causes hilarity to ensue when
			// trying to parse everything correctly.
			// If the original RVA given to this function is equal to
			// the next one to parse, we assume that it's a trick.
			// Instead of raising a PEFormatError this would skip some
			// reasonable data so we just break.
			// 9ee4d0a0caf095314fd7041a3e4404dc is the offending sample.
			if intInSlice(baseRVA+OffsetToDirectory, dirs) {
				break
			}

			level++
			dirs = append(dirs, baseRVA+OffsetToDirectory)
			directoryEntry, _ := pe.doParseResourceDirectory(
				baseRVA+OffsetToDirectory,
				size-(rva-baseRVA),
				baseRVA,
				level,
				dirs)

			dirEntries = append(dirEntries, ResourceDirectoryEntry{
				Struct:        *res,
				Name:          entryName,
				ID:            entryID,
				IsResourceDir: true,
				Directory:     directoryEntry})
		} else {
			// data is entry
			dataEntryStruct := pe.parseResourceDataEntry(baseRVA +
				OffsetToDirectory)
			entryData := ResourceDataEntry{
				Struct:  dataEntryStruct,
				Lang:    ResourceLang(res.Name & 0x3ff),
				SubLang: ResourceSubLang(res.Name >> 10),
			}

			dirEntries = append(dirEntries, ResourceDirectoryEntry{
				Struct:        *res,
				Name:          entryName,
				ID:            entryID,
				IsResourceDir: false,
				Data:          entryData})
		}

		rva += uint32(binary.Size(res))
	}

	return ResourceDirectory{
		Struct:  resourceDir,
		Entries: dirEntries,
	}, nil
}

// The resource directory contains resources like dialog templates, icons,
// and bitmaps. The resources are found in a section called .rsrc section.
func (pe *File) parseResourceDirectory(rva, size uint32) error {
	var dirs []uint32
	Resources, err := pe.doParseResourceDirectory(rva, size, 0, 0, dirs)
	if err != nil {
		return err
	}

	pe.Resources = Resources
	pe.HasResource = true
	return err
}

// String stringify the resource type.
func (rt ResourceType) String() string {

	rsrcTypeMap := map[ResourceType]string{
		RTCursor:       "Cursor",
		RTBitmap:       "Bitmap",
		RTIcon:         "Icon",
		RTMenu:         "Menu",
		RTDialog:       "Dialog box",
		RTString:       "String",
		RTFontDir:      "Font directory",
		RTFont:         "Font",
		RTAccelerator:  "Accelerator",
		RTRCdata:       "RC Data",
		RTMessageTable: "Message Table",
		RTGroupCursor:  "Group Cursor",
		RTGroupIcon:    "Group Icon",
		RTVersion:      "Version",
		RTDlgInclude:   "Dialog Include",
		RTPlugPlay:     "Plug & Play",
		RTVxD:          "VxD",
		RTAniCursor:    "Animated Cursor",
		RTAniIcon:      "Animated Icon",
		RTHtml:         "HTML",
		RTManifest:     "Manifest",
	}

	return rsrcTypeMap[rt]
}

// String stringify the resource language.
func (lang ResourceLang) String() string {

	rsrcLangMap := map[ResourceLang]string{
		LangNeutral:                   "Neutral",
		LangInvariant:                 "Invariant",
		LangAfar:                      "Afar (aa)",
		LangAfrikaans:                 "Afrikaans (af)",
		LangAghem:                     "Aghem (agq)",
		LangAkan:                      "Akan (ak)",
		LangAlbanian:                  "Albanian (sq)",
		LangAlsatian:                  "Alsatian (gsw)",
		LangAmharic:                   "Amharic (am)",
		LangArabic:                    "Arabic (ar)",
		LangArmenian:                  "Armenian (hy)",
		LangAssamese:                  "Assamese (as)",
		LangAsturian:                  "Asturian (ast)",
		LangAsu:                       "Asu (asa)",
		LangAzerbaijaniLatin:          "Azerbaijani (Latin) (az)",
		LangBafia:                     "Bafia (ksf)",
		LangBamanankan:                "Bamanankan (bm)",
		LangBangla:                    "Bangla (bn)",
		LangBasaa:                     "Basaa (bas)",
		LangBashkir:                   "Bashkir (ba)",
		LangBasque:                    "Basque (eu)",
		LangBelarusian:                "Belarusian (be)",
		LangBemba:                     "Bemba (bem)",
		LangBena:                      "Bena (bez)",
		LangBlin:                      "Blin (byn)",
		LangBodo:                      "Bodo (brx)",
		LangBosnianLatin:              "Bosnian (Latin) (bs)",
		LangBreton:                    "Breton (br)",
		LangBulgarian:                 "Bulgarian (bg)",
		LangBurmese:                   "Burmese (my)",
		LangCatalan:                   "Catalan (ca)",
		LangCebuano:                   "Cebuano (ceb)",
		LangCentralKurdish:            "Central Kurdish (ku)",
		LangChakma:                    "Chakma (ccp)",
		LangCherokee:                  "Cherokee (chr)",
		LangChiga:                     "Chiga (cgg)",
		LangChineseSimplified:         "Chinese (Simplified) (zh)",
		LangCongoSwahili:              "Congo Swahili (swc)",
		LangCornish:                   "Cornish (kw)",
		LangCorsican:                  "Corsican (co)",
		LangCroatian:                  "Croatian (hr)",
		LangCzech:                     "Czech (cs)",
		LangDanish:                    "Danish (da)",
		LangDari:                      "Dari (prs)",
		LangDivehi:                    "Divehi (dv)",
		LangDuala:                     "Duala (dua)",
		LangDutch:                     "Dutch (nl)",
		LangDzongkha:                  "Dzongkha (dz)",
		LangEmbu:                      "Embu (ebu)",
		LangEnglish:                   "English (en)",
		LangEsperanto:                 "Esperanto (eo)",
		LangEstonian:                  "Estonian (et)",
		LangEwe:                       "Ewe (ee)",
		LangEwondo:                    "Ewondo (ewo)",
		LangFaroese:                   "Faroese (fo)",
		LangFilipino:                  "Filipino (fil)",
		LangFinnish:                   "Finnish (fi)",
		LangFrench:                    "French (fr)",
		LangFrisian:                   "Frisian (fy)",
		LangFriulian:                  "Friulian (fur)",
		LangFulah:                     "Fulah (ff)",
		LangGalician:                  "Galician (gl)",
		LangGanda:                     "Ganda (lg)",
		LangGeorgian:                  "Georgian (ka)",
		LangGerman:                    "German (de)",
		LangGreek:                     "Greek (el)",
		LangGreenlandic:               "Greenlandic (kl)",
		LangGuarani:                   "Guarani (gn)",
		LangGujarati:                  "Gujarati (gu)",
		LangGusii:                     "Gusii (guz)",
		LangHausaLatin:                "Hausa (Latin) (ha)",
		LangHawaiian:                  "Hawaiian (haw)",
		LangHebrew:                    "Hebrew (he)",
		LangHindi:                     "Hindi (hi)",
		LangHungarian:                 "Hungarian (hu)",
		LangIcelandic:                 "Icelandic (is)",
		LangIgbo:                      "Igbo (ig)",
		LangIndonesian:                "Indonesian (id)",
		LangInterlingua:               "Interlingua (ia)",
		LangInuktitutLatin:            "Inuktitut (Latin) (iu)",
		LangIrish:                     "Irish (ga)",
		LangItalian:                   "Italian (it)",
		LangJapanese:                  "Japanese (ja)",
		LangJavanese:                  "Javanese (jv)",
		LangJolaFonyi:                 "Jola-Fonyi (dyo)",
		LangKabuverdianu:              "Kabuverdianu (kea)",
		LangKabyle:                    "Kabyle (kab)",
		LangKako:                      "Kako (kkj)",
		LangKalenjin:                  "Kalenjin (kln)",
		LangKamba:                     "Kamba (kam)",
		LangKannada:                   "Kannada (kn)",
		LangKashmiri:                  "Kashmiri (ks)",
		LangKazakh:                    "Kazakh (kk)",
		LangKhmer:                     "Khmer (km)",
		LangKiche:                     "K'iche (quc)",
		LangKikuyu:                    "Kikuyu (ki)",
		LangKinyarwanda:               "Kinyarwanda (rw)",
		LangKiswahili:                 "Kiswahili (sw)",
		LangKonkani:                   "Konkani (kok)",
		LangKorean:                    "Korean (ko)",
		LangKoyraChiini:               "Koyra Chiini (khq)",
		LangKoyraboroSenni:            "Koyraboro Senni (ses)",
		LangKwasio:                    "Kwasio (nmg)",
		LangKyrgyz:                    "Kyrgyz (ky)",
		LangLakota:                    "Lakota (lkt)",
		LangLangi:                     "Langi (lag)",
		LangLao:                       "Lao (lo)",
		LangLatvian:                   "Latvian (lv)",
		LangLingala:                   "Lingala (ln)",
		LangLithuanian:                "Lithuanian (lt)",
		LangLowGerman:                 "Low German (nds)",
		LangLowerSorbian:              "Lower Sorbian (dsb)",
		LangLubaKatanga:               "Luba-Katanga (lu)",
		LangLuo:                       "Luo (luo)",
		LangLuxembourgish:             "Luxembourgish (lb)",
		LangLuyia:                     "Luyia (luy)",
		LangMacedonian:                "Macedonian (mk)",
		LangMachame:                   "Machame (jmc)",
		LangMakhuwaMeetto:             "Makhuwa-Meetto (mgh)",
		LangMakonde:                   "Makonde (kde)",
		LangMalagasy:                  "Malagasy (mg)",
		LangMalay:                     "Malay (ms)",
		LangMalayalam:                 "Malayalam (ml)",
		LangMaltese:                   "Maltese (mt)",
		LangManx:                      "Manx (gv)",
		LangMaori:                     "Maori (mi)",
		LangMapudungun:                "Mapudungun (arn)",
		LangMarathi:                   "Marathi (mr)",
		LangMasai:                     "Masai (mas)",
		LangMeru:                      "Meru (mer)",
		LangMeta:                      "Meta' (mgo)",
		LangMohawk:                    "Mohawk (moh)",
		LangMongolianCyrillic:         "Mongolian (Cyrillic) (mn)",
		LangMorisyen:                  "Morisyen (mfe)",
		LangMundang:                   "Mundang (mua)",
		LangNko:                       "N'ko (nqo)",
		LangNama:                      "Nama (naq)",
		LangNepali:                    "Nepali (ne)",
		LangNgiemboon:                 "Ngiemboon (nnh)",
		LangNgomba:                    "Ngomba (jgo)",
		LangNorthNdebele:              "North Ndebele (nd)",
		LangNorwegianBokmal:           "Norwegian (Bokmal) (no)",
		LangNorwegianBokmal:           "Norwegian (Bokmal) (nb)",
		LangNorwegianNynorsk:          "Norwegian (Nynorsk) (nn)",
		LangNuer:                      "Nuer (nus)",
		LangNyankole:                  "Nyankole (nyn)",
		LangOccitan:                   "Occitan (oc)",
		LangOdia:                      "Odia (or)",
		LangOromo:                     "Oromo (om)",
		LangOssetian:                  "Ossetian (os)",
		LangPashto:                    "Pashto (ps)",
		LangPersian:                   "Persian (fa)",
		LangPolish:                    "Polish (pl)",
		LangPortuguese:                "Portuguese (pt)",
		LangPunjabi:                   "Punjabi (pa)",
		LangQuechua:                   "Quechua (quz)",
		LangRipuarian:                 "Ripuarian (ksh)",
		LangRomanian:                  "Romanian (ro)",
		LangRomansh:                   "Romansh (rm)",
		LangRombo:                     "Rombo (rof)",
		LangRundi:                     "Rundi (rn)",
		LangRussian:                   "Russian (ru)",
		LangRwa:                       "Rwa (rwk)",
		LangSaho:                      "Saho (ssy)",
		LangSakha:                     "Sakha (sah)",
		LangSamburu:                   "Samburu (saq)",
		LangSamiInari:                 "Sami (Inari) (smn)",
		LangSamiLule:                  "Sami (Lule) (smj)",
		LangSamiNorthern:              "Sami (Northern) (se)",
		LangSamiSkolt:                 "Sami (Skolt) (sms)",
		LangSamiSouthern:              "Sami (Southern) (sma)",
		LangSango:                     "Sango (sg)",
		LangSangu:                     "Sangu (sbp)",
		LangSanskrit:                  "Sanskrit (sa)",
		LangScottishGaelic:            "Scottish Gaelic (gd)",
		LangSena:                      "Sena (seh)",
		LangSerbianLatin:              "Serbian (Latin) (sr)",
		LangSesothoSaLeboa:            "Sesotho Sa Leboa (nso)",
		LangSetswana:                  "Setswana (tn)",
		LangShambala:                  "Shambala (ksb)",
		LangShona:                     "Shona (sn)",
		LangSindhi:                    "Sindhi (sd)",
		LangSinhala:                   "Sinhala (si)",
		LangSlovak:                    "Slovak (sk)",
		LangSlovenian:                 "Slovenian (sl)",
		LangSoga:                      "Soga (xog)",
		LangSomali:                    "Somali (so)",
		LangSotho:                     "Sotho (st)",
		LangSouthNdebele:              "South Ndebele (nr)",
		LangSpanish:                   "Spanish (es)",
		LangStandardMoroccanTamazight: "Standard Moroccan Tamazight (zgh)",
		LangSwati:                     "Swati (ss)",
		LangSwedish:                   "Swedish (sv)",
		LangSyriac:                    "Syriac (syr)",
		LangTachelhit:                 "Tachelhit (shi)",
		LangTaita:                     "Taita (dav)",
		LangTajikCyrillic:             "Tajik (Cyrillic) (tg)",
		LangTamazightLatin:            "Tamazight (Latin) (tzm)",
		LangTamil:                     "Tamil (ta)",
		LangTasawaq:                   "Tasawaq (twq)",
		LangTatar:                     "Tatar (tt)",
		LangTelugu:                    "Telugu (te)",
		LangTeso:                      "Teso (teo)",
		LangThai:                      "Thai (th)",
		LangTibetan:                   "Tibetan (bo)",
		LangTigre:                     "Tigre (tig)",
		LangTigrinya:                  "Tigrinya (ti)",
		LangTongan:                    "Tongan (to)",
		LangTsonga:                    "Tsonga (ts)",
		LangTurkish:                   "Turkish (tr)",
		LangTurkmen:                   "Turkmen (tk)",
		LangUkrainian:                 "Ukrainian (uk)",
		LangUpperSorbian:              "Upper Sorbian (hsb)",
		LangUrdu:                      "Urdu (ur)",
		LangUyghur:                    "Uyghur (ug)",
		LangUzbekLatin:                "Uzbek (Latin) (uz)",
		LangVai:                       "Vai (vai)",
		LangVenda:                     "Venda (ve)",
		LangVietnamese:                "Vietnamese (vi)",
		LangVolapük:                   "Volapük (vo)",
		LangVunjo:                     "Vunjo (vun)",
		LangWalser:                    "Walser (wae)",
		LangWelsh:                     "Welsh (cy)",
		LangWolaytta:                  "Wolaytta (wal)",
		LangWolof:                     "Wolof (wo)",
		LangXhosa:                     "Xhosa (xh)",
		LangYangben:                   "Yangben (yav)",
		LangYi:                        "Yi (ii)",
		LangYoruba:                    "Yoruba (yo)",
		LangZarma:                     "Zarma (dje)",
		LangZulu:                      "Zulu (zu)",
	}

	if val, ok := rsrcLangMap[lang]; ok {
		return val
	}

	return "?"
}

// String stringify the resource sub language.
func (subLang ResourceSubLang) String() string {

	rsrcSubLangMap := map[ResourceSubLang]string{
		SubLangAfarDjibouti:                            "Afar Djibouti (aa-DJ)",
		SubLangAfarEritrea:                             "Afar Eritrea (aa-ER)",
		SubLangAfarEthiopia:                            "Afar Ethiopia (aa-ET)",
		SubLangAfrikaansNamibia:                        "Afrikaans Namibia (af-NA)",
		SubLangAfrikaansSouthAfrica:                    "Afrikaans South Africa (af-ZA)",
		SubLangAghemCameroon:                           "Aghem Cameroon (agq-CM)",
		SubLangAkanGhana:                               "Akan Ghana (ak-GH)",
		SubLangAlbanianAlbania:                         "Albanian Albania (sq-AL)",
		SubLangAlbanianNorthMacedonia:                  "Albanian North Macedonia (sq-MK)",
		SubLangAlsatianFrance:                          "Alsatian France (gsw-FR)",
		SubLangAlsatianLiechtenstein:                   "Alsatian Liechtenstein (gsw-LI)",
		SubLangAlsatianSwitzerland:                     "Alsatian Switzerland (gsw-CH)",
		SubLangAmharicEthiopia:                         "Amharic Ethiopia (am-ET)",
		SubLangArabicAlgeria:                           "Arabic Algeria (ar-DZ)",
		SubLangArabicBahrain:                           "Arabic Bahrain (ar-BH)",
		SubLangArabicChad:                              "Arabic Chad (ar-TD)",
		SubLangArabicComoros:                           "Arabic Comoros (ar-KM)",
		SubLangArabicDjibouti:                          "Arabic Djibouti (ar-DJ)",
		SubLangArabicEgypt:                             "Arabic Egypt (ar-EG)",
		SubLangArabicEritrea:                           "Arabic Eritrea (ar-ER)",
		SubLangArabicIraq:                              "Arabic Iraq (ar-IQ)",
		SubLangArabicIsrael:                            "Arabic Israel (ar-IL)",
		SubLangArabicJordan:                            "Arabic Jordan (ar-JO)",
		SubLangArabicKuwait:                            "Arabic Kuwait (ar-KW)",
		SubLangArabicLebanon:                           "Arabic Lebanon (ar-LB)",
		SubLangArabicLibya:                             "Arabic Libya (ar-LY)",
		SubLangArabicMauritania:                        "Arabic Mauritania (ar-MR)",
		SubLangArabicMorocco:                           "Arabic Morocco (ar-MA)",
		SubLangArabicOman:                              "Arabic Oman (ar-OM)",
		SubLangArabicPalestinianAuthority:              "Arabic Palestinian Authority (ar-PS)",
		SubLangArabicQatar:                             "Arabic Qatar (ar-QA)",
		SubLangArabicSaudiArabia:                       "Arabic Saudi Arabia (ar-SA)",
		SubLangArabicSomalia:                           "Arabic Somalia (ar-SO)",
		SubLangArabicSouthSudan:                        "Arabic South Sudan (ar-SS)",
		SubLangArabicSudan:                             "Arabic Sudan (ar-SD)",
		SubLangArabicSyria:                             "Arabic Syria (ar-SY)",
		SubLangArabicTunisia:                           "Arabic Tunisia (ar-TN)",
		SubLangArabicUae:                               "Arabic U.a.e. (ar-AE)",
		SubLangArabicWorld:                             "Arabic World (ar-001)",
		SubLangArabicYemen:                             "Arabic Yemen (ar-YE)",
		SubLangArmenianArmenia:                         "Armenian Armenia (hy-AM)",
		SubLangAssameseIndia:                           "Assamese India (as-IN)",
		SubLangAsturianSpain:                           "Asturian Spain (ast-ES)",
		SubLangAsuTanzania:                             "Asu Tanzania (asa-TZ)",
		SubLangAzerbaijaniCyrillic:                     "Azerbaijani (Cyrillic) (az-Cyrl)",
		SubLangAzerbaijaniCyrillicAzerbaijan:           "Azerbaijani (Cyrillic) Azerbaijan (az-Cyrl-AZ)",
		SubLangAzerbaijaniLatin:                        "Azerbaijani (Latin) (az-Latn)",
		SubLangAzerbaijaniLatinAzerbaijan:              "Azerbaijani (Latin) Azerbaijan (az-Latn-AZ)",
		SubLangBafiaCameroon:                           "Bafia Cameroon (ksf-CM)",
		SubLangBamanankanLatinMali:                     "Bamanankan (Latin) Mali (bm-Latn-ML)",
		SubLangBanglaBangladesh:                        "Bangla Bangladesh (bn-BD)",
		SubLangBanglaIndia:                             "Bangla India (bn-IN)",
		SubLangBasaaCameroon:                           "Basaa Cameroon (bas-CM)",
		SubLangBashkirRussia:                           "Bashkir Russia (ba-RU)",
		SubLangBasqueSpain:                             "Basque Spain (eu-ES)",
		SubLangBelarusianBelarus:                       "Belarusian Belarus (be-BY)",
		SubLangBembaZambia:                             "Bemba Zambia (bem-ZM)",
		SubLangBenaTanzania:                            "Bena Tanzania (bez-TZ)",
		SubLangBlinEritrea:                             "Blin Eritrea (byn-ER)",
		SubLangBodoIndia:                               "Bodo India (brx-IN)",
		SubLangBosnianCyrillic:                         "Bosnian (Cyrillic) (bs-Cyrl)",
		SubLangBosnianCyrillicBosniaAndHerzegovina:     "Bosnian (Cyrillic) Bosnia And Herzegovina (bs-Cyrl-BA)",
		SubLangBosnianLatin:                            "Bosnian (Latin) (bs-Latn)",
		SubLangBosnianLatinBosniaAndHerzegovina:        "Bosnian (Latin) Bosnia And Herzegovina (bs-Latn-BA)",
		SubLangBretonFrance:                            "Breton France (br-FR)",
		SubLangBulgarianBulgaria:                       "Bulgarian Bulgaria (bg-BG)",
		SubLangBurmeseMyanmar:                          "Burmese Myanmar (my-MM)",
		SubLangCatalanAndorra:                          "Catalan Andorra (ca-AD)",
		SubLangCatalanFrance:                           "Catalan France (ca-FR)",
		SubLangCatalanItaly:                            "Catalan Italy (ca-IT)",
		SubLangCatalanSpain:                            "Catalan Spain (ca-ES)",
		SubLangCebuanLatin:                             "Cebuan (Latin) (ceb-Latn)",
		SubLangCebuanLatinPhilippines:                  "Cebuan (Latin) Philippines (ceb-Latn-PH)",
		SubLangCentralAtlasTamazightArabicMorocco:      "Central Atlas Tamazight (Arabic) Morocco (tzm-ArabMA)",
		SubLangCentralAtlasTamazightLatinMorocco:       "Central Atlas Tamazight (Latin) Morocco (tzm-LatnMA)",
		SubLangCentralKurdish:                          "Central Kurdish (ku-Arab)",
		SubLangCentralKurdishIraq:                      "Central Kurdish Iraq (ku-Arab-IQ)",
		SubLangChakmaChakma:                            "Chakma Chakma (ccp-Cakm)",
		SubLangChakmaBangladesh:                        "Chakma Bangladesh (ccp-CakmBD)",
		SubLangChakmaIndia:                             "Chakma India (ccp-CakmIN)",
		SubLangChechenRussia:                           "Chechen Russia (ce-RU)",
		SubLangCherokee:                                "Cherokee (chr-Cher)",
		SubLangCherokeeUnitedStates:                    "Cherokee United States (chr-Cher-US)",
		SubLangChigaUganda:                             "Chiga Uganda (cgg-UG)",
		SubLangChineseSimplified:                       "Chinese (Simplified) (zh-Hans)",
		SubLangChineseSimplifiedPeoplesRepublicOfChina: "Chinese (Simplified) People's Republic Of China (zh-CN)",
		SubLangChineseSimplifiedSingapore:              "Chinese (Simplified) Singapore (zh-SG)",
		SubLangChineseTraditional:                      "Chinese (Traditional) (zh-Hant)",
		SubLangChineseTraditionalHongKongSar:           "Chinese (Traditional) Hong Kong S.a.r. (zh-HK)",
		SubLangChineseTraditionalMacaoSar:              "Chinese (Traditional) Macao S.a.r. (zh-MO)",
		SubLangChineseTraditionalTaiwan:                "Chinese (Traditional) Taiwan (zh-TW)",
		SubLangChurchSlavicRussia:                      "Church Slavic Russia (cu-RU)",
		SubLangCongoSwahiliCongoDrc:                    "Congo Swahili Congo Drc (swc-CD)",
		SubLangCornishUnitedKingdom:                    "Cornish United Kingdom (kw-GB)",
		SubLangCorsicanFrance:                          "Corsican France (co-FR)",
		SubLangCroatianCroatia:                         "Croatian Croatia (hr-HR)",
		SubLangCroatianLatinBosniaAndHerzegovina:       "Croatian (Latin) Bosnia And Herzegovina (hr-BA)",
		SubLangCzechCzechRepublic:                      "Czech Czech Republic (cs-CZ)",
		SubLangDanishDenmark:                           "Danish Denmark (da-DK)",
		SubLangDanishGreenland:                         "Danish Greenland (da-GL)",
		SubLangDariAfghanistan:                         "Dari Afghanistan (prs-AF)",
		SubLangDivehiMaldives:                          "Divehi Maldives (dv-MV)",
		SubLangDualaCameroon:                           "Duala Cameroon (dua-CM)",
		SubLangDutchAruba:                              "Dutch Aruba (nl-AW)",
		SubLangDutchBelgium:                            "Dutch Belgium (nl-BE)",
		SubLangDutchBonaireSintEustatiusAndSaba:        "Dutch Bonaire, Sint Eustatius And Saba (nl-BQ)",
		SubLangDutchCuraçao:                            "Dutch Curaçao (nl-CW)",
		SubLangDutchNetherlands:                        "Dutch Netherlands (nl-NL)",
		SubLangDutchSintMaarten:                        "Dutch Sint Maarten (nl-SX)",
		SubLangDutchSuriname:                           "Dutch Suriname (nl-SR)",
		SubLangDzongkhaBhutan:                          "Dzongkha Bhutan (dz-BT)",
		SubLangEmbuKenya:                               "Embu Kenya (ebu-KE)",
		SubLangEnglishAmericanSamoa:                    "English American Samoa (en-AS)",
		SubLangEnglishAnguilla:                         "English Anguilla (en-AI)",
		SubLangEnglishAntiguaAndBarbuda:                "English Antigua And Barbuda (en-AG)",
		SubLangEnglishAustralia:                        "English Australia (en-AU)",
		SubLangEnglishAustria:                          "English Austria (en-AT)",
		SubLangEnglishBahamas:                          "English Bahamas (en-BS)",
		SubLangEnglishBarbados:                         "English Barbados (en-BB)",
		SubLangEnglishBelgium:                          "English Belgium (en-BE)",
		SubLangEnglishBelize:                           "English Belize (en-BZ)",
		SubLangEnglishBermuda:                          "English Bermuda (en-BM)",
		SubLangEnglishBotswana:                         "English Botswana (en-BW)",
		SubLangEnglishBritishIndianOceanTerritory:      "English British Indian Ocean Territory (en-IO)",
		SubLangEnglishBritishVirginIslands:             "English British Virgin Islands (en-VG)",
		SubLangEnglishBurundi:                          "English Burundi (en-BI)",
		SubLangEnglishCameroon:                         "English Cameroon (en-CM)",
		SubLangEnglishCanada:                           "English Canada (en-CA)",
		SubLangEnglishCaribbean:                        "English Caribbean (en-029)",
		SubLangEnglishCaymanIslands:                    "English Cayman Islands (en-KY)",
		SubLangEnglishChristmasIsland:                  "English Christmas Island (en-CX)",
		SubLangEnglishCocosKeelingIslands:              "English Cocos [Keeling] Islands (en-CC)",
		SubLangEnglishCookIslands:                      "English Cook Islands (en-CK)",
		SubLangEnglishCyprus:                           "English Cyprus (en-CY)",
		SubLangEnglishDenmark:                          "English Denmark (en-DK)",
		SubLangEnglishDominica:                         "English Dominica (en-DM)",
		SubLangEnglishEritrea:                          "English Eritrea (en-ER)",
		SubLangEnglishEurope:                           "English Europe (en-150)",
		SubLangEnglishFalklandIslands:                  "English Falkland Islands (en-FK)",
		SubLangEnglishFinland:                          "English Finland (en-FI)",
		SubLangEnglishFiji:                             "English Fiji (en-FJ)",
		SubLangEnglishGambia:                           "English Gambia (en-GM)",
		SubLangEnglishGermany:                          "English Germany (en-DE)",
		SubLangEnglishGhana:                            "English Ghana (en-GH)",
		SubLangEnglishGibraltar:                        "English Gibraltar (en-GI)",
		SubLangEnglishGrenada:                          "English Grenada (en-GD)",
		SubLangEnglishGuam:                             "English Guam (en-GU)",
		SubLangEnglishGuernsey:                         "English Guernsey (en-GG)",
		SubLangEnglishGuyana:                           "English Guyana (en-GY)",
		SubLangEnglishHongKong:                         "English Hong Kong (en-HK)",
		SubLangEnglishIndia:                            "English India (en-IN)",
		SubLangEnglishIreland:                          "English Ireland (en-IE)",
		SubLangEnglishIsleOfMan:                        "English Isle Of Man (en-IM)",
		SubLangEnglishIsrael:                           "English Israel (en-IL)",
		SubLangEnglishJamaica:                          "English Jamaica (en-JM)",
		SubLangEnglishJersey:                           "English Jersey (en-JE)",
		SubLangEnglishKenya:                            "English Kenya (en-KE)",
		SubLangEnglishKiribati:                         "English Kiribati (en-KI)",
		SubLangEnglishLesotho:                          "English Lesotho (en-LS)",
		SubLangEnglishLiberia:                          "English Liberia (en-LR)",
		SubLangEnglishMacaoSar:                         "English Macao Sar (en-MO)",
		SubLangEnglishMadagascar:                       "English Madagascar (en-MG)",
		SubLangEnglishMalawi:                           "English Malawi (en-MW)",
		SubLangEnglishMalaysia:                         "English Malaysia (en-MY)",
		SubLangEnglishMalta:                            "English Malta (en-MT)",
		SubLangEnglishMarshallIslands:                  "English Marshall Islands (en-MH)",
		SubLangEnglishMauritius:                        "English Mauritius (en-MU)",
		SubLangEnglishMicronesia:                       "English Micronesia (en-FM)",
		SubLangEnglishMontserrat:                       "English Montserrat (en-MS)",
		SubLangEnglishNamibia:                          "English Namibia (en-NA)",
		SubLangEnglishNauru:                            "English Nauru (en-NR)",
		SubLangEnglishNetherlands:                      "English Netherlands (en-NL)",
		SubLangEnglishNewZealand:                       "English New Zealand (en-NZ)",
		SubLangEnglishNigeria:                          "English Nigeria (en-NG)",
		SubLangEnglishNiue:                             "English Niue (en-NU)",
		SubLangEnglishNorfolkIsland:                    "English Norfolk Island (en-NF)",
		SubLangEnglishNorthernMarianaIslands:           "English Northern Mariana Islands (en-MP)",
		SubLangEnglishPakistan:                         "English Pakistan (en-PK)",
		SubLangEnglishPalau:                            "English Palau (en-PW)",
		SubLangEnglishPapuaNewGuinea:                   "English Papua New Guinea (en-PG)",
		SubLangEnglishPitcairnIslands:                  "English Pitcairn Islands (en-PN)",
		SubLangEnglishPuertoRico:                       "English Puerto Rico (en-PR)",
		SubLangEnglishRepublicOfThePhilippines:         "English Republic Of The Philippines (en-PH)",
		SubLangEnglishRwanda:                           "English Rwanda (en-RW)",
		SubLangEnglishSaintKittsAndNevis:               "English Saint Kitts And Nevis (en-KN)",
		SubLangEnglishSaintLucia:                       "English Saint Lucia (en-LC)",
		SubLangEnglishSaintVincentAndTheGrenadines:     "English Saint Vincent And The Grenadines (en-VC)",
		SubLangEnglishSamoa:                            "English Samoa (en-WS)",
		SubLangEnglishSeychelles:                       "English Seychelles (en-SC)",
		SubLangEnglishSierraLeone:                      "English Sierra Leone (en-SL)",
		SubLangEnglishSingapore:                        "English Singapore (en-SG)",
		SubLangEnglishSintMaarten:                      "English Sint Maarten (en-SX)",
		SubLangEnglishSlovenia:                         "English Slovenia (en-SI)",
		SubLangEnglishSolomonIslands:                   "English Solomon Islands (en-SB)",
		SubLangEnglishSouthAfrica:                      "English South Africa (en-ZA)",
		SubLangEnglishSouthSudan:                       "English South Sudan (en-SS)",
		SubLangEnglishStHelenaAscensionTristanDaCunha:  "English St Helena, Ascension, Tristan Da Cunha (en-SH)",
		SubLangEnglishSudan:                            "English Sudan (en-SD)",
		SubLangEnglishSwaziland:                        "English Swaziland (en-SZ)",
		SubLangEnglishSweden:                           "English Sweden (en-SE)",
		SubLangEnglishSwitzerland:                      "English Switzerland (en-CH)",
		SubLangEnglishTanzania:                         "English Tanzania (en-TZ)",
		SubLangEnglishTokelau:                          "English Tokelau (en-TK)",
		SubLangEnglishTonga:                            "English Tonga (en-TO)",
		SubLangEnglishTrinidadAndTobago:                "English Trinidad And Tobago (en-TT)",
		SubLangEnglishTurksAndCaicosIslands:            "English Turks And Caicos Islands (en-TC)",
		SubLangEnglishTuvalu:                           "English Tuvalu (en-TV)",
		SubLangEnglishUganda:                           "English Uganda (en-UG)",
		SubLangEnglishUnitedArabEmirates:               "English United Arab Emirates (en-AE)",
		SubLangEnglishUnitedKingdom:                    "English United Kingdom (en-GB)",
		SubLangEnglishUnitedStates:                     "English United States (en-US)",
		SubLangEnglishUsMinorOutlyingIslands:           "English Us Minor Outlying Islands (en-UM)",
		SubLangEnglishUsVirginIslands:                  "English Us Virgin Islands (en-VI)",
		SubLangEnglishVanuatu:                          "English Vanuatu (en-VU)",
		SubLangEnglishWorld:                            "English World (en-001)",
		SubLangEnglishZambia:                           "English Zambia (en-ZM)",
		SubLangEnglishZimbabwe:                         "English Zimbabwe (en-ZW)",
		SubLangEsperantoWorld:                          "Esperanto World (eo-001)",
		SubLangEstonianEstonia:                         "Estonian Estonia (et-EE)",
		SubLangEweGhana:                                "Ewe Ghana (ee-GH)",
		SubLangEweTogo:                                 "Ewe Togo (ee-TG)",
		SubLangEwondoCameroon:                          "Ewondo Cameroon (ewo-CM)",
		SubLangFaroeseDenmark:                          "Faroese Denmark (fo-DK)",
		SubLangFaroeseFaroeIslands:                     "Faroese Faroe Islands (fo-FO)",
		SubLangFilipinoPhilippines:                     "Filipino Philippines (fil-PH)",
		SubLangFinnishFinland:                          "Finnish Finland (fi-FI)",
		SubLangFrenchAlgeria:                           "French Algeria (fr-DZ)",
		SubLangFrenchBelgium:                           "French Belgium (fr-BE)",
		SubLangFrenchBenin:                             "French Benin (fr-BJ)",
		SubLangFrenchBurkinaFaso:                       "French Burkina Faso (fr-BF)",
		SubLangFrenchBurundi:                           "French Burundi (fr-BI)",
		SubLangFrenchCameroon:                          "French Cameroon (fr-CM)",
		SubLangFrenchCanada:                            "French Canada (fr-CA)",
		SubLangFrenchCaribbean:                         "French Caribbean (fr-029)",
		SubLangFrenchCentralAfricanRepublic:            "French Central African Republic (fr-CF)",
		SubLangFrenchChad:                              "French Chad (fr-TD)",
		SubLangFrenchComoros:                           "French Comoros (fr-KM)",
		SubLangFrenchCongo:                             "French Congo (fr-CG)",
		SubLangFrenchCongoDrc:                          "French Congo, Drc (fr-CD)",
		SubLangFrenchCôteDivoire:                       "French Côte D'ivoire (fr-CI)",
		SubLangFrenchDjibouti:                          "French Djibouti (fr-DJ)",
		SubLangFrenchEquatorialGuinea:                  "French Equatorial Guinea (fr-GQ)",
		SubLangFrenchFrance:                            "French France (fr-FR)",
		SubLangFrenchFrenchGuiana:                      "French French Guiana (fr-GF)",
		SubLangFrenchFrenchPolynesia:                   "French French Polynesia (fr-PF)",
		SubLangFrenchGabon:                             "French Gabon (fr-GA)",
		SubLangFrenchGuadeloupe:                        "French Guadeloupe (fr-GP)",
		SubLangFrenchGuinea:                            "French Guinea (fr-GN)",
		SubLangFrenchHaiti:                             "French Haiti (fr-HT)",
		SubLangFrenchLuxembourg:                        "French Luxembourg (fr-LU)",
		SubLangFrenchMadagascar:                        "French Madagascar (fr-MG)",
		SubLangFrenchMali:                              "French Mali (fr-ML)",
		SubLangFrenchMartinique:                        "French Martinique (fr-MQ)",
		SubLangFrenchMauritania:                        "French Mauritania (fr-MR)",
		SubLangFrenchMauritius:                         "French Mauritius (fr-MU)",
		SubLangFrenchMayotte:                           "French Mayotte (fr-YT)",
		SubLangFrenchMorocco:                           "French Morocco (fr-MA)",
		SubLangFrenchNewCaledonia:                      "French New Caledonia (fr-NC)",
		SubLangFrenchNiger:                             "French Niger (fr-NE)",
		SubLangFrenchPrincipalityOfMonaco:              "French Principality Of Monaco (fr-MC)",
		SubLangFrenchReunion:                           "French Reunion (fr-RE)",
		SubLangFrenchRwanda:                            "French Rwanda (fr-RW)",
		SubLangFrenchSaintBarthélemy:                   "French Saint Barthélemy (fr-BL)",
		SubLangFrenchSaintMartin:                       "French Saint Martin (fr-MF)",
		SubLangFrenchSaintPierreAndMiquelon:            "French Saint Pierre And Miquelon (fr-PM)",
		SubLangFrenchSenegal:                           "French Senegal (fr-SN)",
		SubLangFrenchSeychelles:                        "French Seychelles (fr-SC)",
		SubLangFrenchSwitzerland:                       "French Switzerland (fr-CH)",
		SubLangFrenchSyria:                             "French Syria (fr-SY)",
		SubLangFrenchTogo:                              "French Togo (fr-TG)",
		SubLangFrenchTunisia:                           "French Tunisia (fr-TN)",
		SubLangFrenchVanuatu:                           "French Vanuatu (fr-VU)",
		SubLangFrenchWallisAndFutuna:                   "French Wallis And Futuna (fr-WF)",
		SubLangFrisianNetherlands:                      "Frisian Netherlands (fy-NL)",
		SubLangFriulianItaly:                           "Friulian Italy (fur-IT)",
		SubLangFulahLatin:                              "Fulah (Latin) (ff-Latn)",
		SubLangFulahLatinBurkinaFaso:                   "Fulah (Latin) Burkina Faso (ff-Latn-BF)",
		SubLangFulahCameroon:                           "Fulah Cameroon (ff-CM)",
		SubLangFulahLatinCameroon:                      "Fulah (Latin) Cameroon (ff-Latn-CM)",
		SubLangFulahLatinGambia:                        "Fulah (Latin) Gambia (ff-Latn-GM)",
		SubLangFulahLatinGhana:                         "Fulah (Latin) Ghana (ff-Latn-GH)",
		SubLangFulahGuinea:                             "Fulah Guinea (ff-GN)",
		SubLangFulahLatinGuinea:                        "Fulah (Latin) Guinea (ff-Latn-GN)",
		SubLangFulahLatinGuineaBissau:                  "Fulah (Latin) Guinea-Bissau (ff-Latn-GW)",
		SubLangFulahLatinLiberia:                       "Fulah (Latin) Liberia (ff-Latn-LR)",
		SubLangFulahMauritania:                         "Fulah Mauritania (ff-MR)",
		SubLangFulahLatinMauritania:                    "Fulah (Latin) Mauritania (ff-Latn-MR)",
		SubLangFulahLatinNiger:                         "Fulah (Latin) Niger (ff-Latn-NE)",
		SubLangFulahNigeria:                            "Fulah Nigeria (ff-NG)",
		SubLangFulahLatinNigeria:                       "Fulah (Latin) Nigeria (ff-Latn-NG)",
		SubLangFulahSenegal:                            "Fulah Senegal (ff-Latn-SN)",
		SubLangFulahLatinSierraLeone:                   "Fulah (Latin) Sierra Leone (ff-Latn-SL)",
		SubLangGalicianSpain:                           "Galician Spain (gl-ES)",
		SubLangGandaUganda:                             "Ganda Uganda (lg-UG)",
		SubLangGeorgianGeorgia:                         "Georgian Georgia (ka-GE)",
		SubLangGermanAustria:                           "German Austria (de-AT)",
		SubLangGermanBelgium:                           "German Belgium (de-BE)",
		SubLangGermanGermany:                           "German Germany (de-DE)",
		SubLangGermanItaly:                             "German Italy (de-IT)",
		SubLangGermanLiechtenstein:                     "German Liechtenstein (de-LI)",
		SubLangGermanLuxembourg:                        "German Luxembourg (de-LU)",
		SubLangGermanSwitzerland:                       "German Switzerland (de-CH)",
		SubLangGreekCyprus:                             "Greek Cyprus (el-CY)",
		SubLangGreekGreece:                             "Greek Greece (el-GR)",
		SubLangGreenlandicGreenland:                    "Greenlandic Greenland (kl-GL)",
		SubLangGuaraniParaguay:                         "Guarani Paraguay (gn-PY)",
		SubLangGujaratiIndia:                           "Gujarati India (gu-IN)",
		SubLangGusiiKenya:                              "Gusii Kenya (guz-KE)",
		SubLangHausaLatin:                              "Hausa (Latin) (ha-Latn)",
		SubLangHausaLatinGhana:                         "Hausa (Latin) Ghana (ha-Latn-GH)",
		SubLangHausaLatinNiger:                         "Hausa (Latin) Niger (ha-Latn-NE)",
		SubLangHausaLatinNigeria:                       "Hausa (Latin) Nigeria (ha-Latn-NG)",
		SubLangHawaiianUnitedStates:                    "Hawaiian United States (haw-US)",
		SubLangHebrewIsrael:                            "Hebrew Israel (he-IL)",
		SubLangHindiIndia:                              "Hindi India (hi-IN)",
		SubLangHungarianHungary:                        "Hungarian Hungary (hu-HU)",
		SubLangIcelandicIceland:                        "Icelandic Iceland (is-IS)",
		SubLangIgboNigeria:                             "Igbo Nigeria (ig-NG)",
		SubLangIndonesianIndonesia:                     "Indonesian Indonesia (id-ID)",
		SubLangInterlinguaFrance:                       "Interlingua France (ia-FR)",
		SubLangInterlinguaWorld:                        "Interlingua World (ia-001)",
		SubLangInuktitutLatin:                          "Inuktitut (Latin) (iu-Latn)",
		SubLangInuktitutLatinCanada:                    "Inuktitut (Latin) Canada (iu-Latn-CA)",
		SubLangInuktitutSyllabics:                      "Inuktitut (Syllabics) (iu-Cans)",
		SubLangInuktitutSyllabicsCanada:                "Inuktitut (Syllabics) Canada (iu-Cans-CA)",
		SubLangIrishIreland:                            "Irish Ireland (ga-IE)",
		SubLangItalianItaly:                            "Italian Italy (it-IT)",
		SubLangItalianSanMarino:                        "Italian San Marino (it-SM)",
		SubLangItalianSwitzerland:                      "Italian Switzerland (it-CH)",
		SubLangItalianVaticanCity:                      "Italian Vatican City (it-VA)",
		SubLangJapaneseJapan:                           "Japanese Japan (ja-JP)",
		SubLangJavaneseLatin:                           "Javanese Latin (jv-Latn)",
		SubLangJavaneseLatinIndonesia:                  "Javanese Latin, Indonesia (jv-Latn-ID)",
		SubLangJolaFonyiSenegal:                        "Jola-Fonyi Senegal (dyo-SN)",
		SubLangKabuverdianuCaboVerde:                   "Kabuverdianu Cabo Verde (kea-CV)",
		SubLangKabyleAlgeria:                           "Kabyle Algeria (kab-DZ)",
		SubLangKakoCameroon:                            "Kako Cameroon (kkj-CM)",
		SubLangKalenjinKenya:                           "Kalenjin Kenya (kln-KE)",
		SubLangKambaKenya:                              "Kamba Kenya (kam-KE)",
		SubLangKannadaIndia:                            "Kannada India (kn-IN)",
		SubLangKanuriLatinNigeria:                      "Kanuri (Latin) Nigeria (kr-Latn-NG)",
		SubLangKashmiriPersoArabic:                     "Kashmiri Perso-Arabic (ks-Arab)",
		SubLangKashmiriPersoArabic:                     "Kashmiri Perso-Arabic (ks-Arab-IN)",
		SubLangKashmiriDevanagariIndia:                 "Kashmiri (Devanagari) India (ks-Deva-IN)",
		SubLangKazakhKazakhstan:                        "Kazakh Kazakhstan (kk-KZ)",
		SubLangKhmerCambodia:                           "Khmer Cambodia (km-KH)",
		SubLangKicheGuatemala:                          "K'iche Guatemala (quc-Latn-GT)",
		SubLangKikuyuKenya:                             "Kikuyu Kenya (ki-KE)",
		SubLangKinyarwandaRwanda:                       "Kinyarwanda Rwanda (rw-RW)",
		SubLangKiswahiliKenya:                          "Kiswahili Kenya (sw-KE)",
		SubLangKiswahiliTanzania:                       "Kiswahili Tanzania (sw-TZ)",
		SubLangKiswahiliUganda:                         "Kiswahili Uganda (sw-UG)",
		SubLangKonkaniIndia:                            "Konkani India (kok-IN)",
		SubLangKoreanKorea:                             "Korean Korea (ko-KR)",
		SubLangKoreanNorthKorea:                        "Korean North Korea (ko-KP)",
		SubLangKoyraChiiniMali:                         "Koyra Chiini Mali (khq-ML)",
		SubLangKoyraboroSenniMali:                      "Koyraboro Senni Mali (ses-ML)",
		SubLangKwasioCameroon:                          "Kwasio Cameroon (nmg-CM)",
		SubLangKyrgyzKyrgyzstan:                        "Kyrgyz Kyrgyzstan (ky-KG)",
		SubLangKurdishPersoArabicIran:                  "Kurdish Perso-Arabic, Iran (ku-Arab-IR)",
		SubLangLakotaUnitedStates:                      "Lakota United States (lkt-US)",
		SubLangLangiTanzania:                           "Langi Tanzania (lag-TZ)",
		SubLangLaoLaoPdr:                               "Lao Lao P.d.r. (lo-LA)",
		SubLangLatinVaticanCity:                        "Latin Vatican City (la-VA)",
		SubLangLatvianLatvia:                           "Latvian Latvia (lv-LV)",
		SubLangLingalaAngola:                           "Lingala Angola (ln-AO)",
		SubLangLingalaCentralAfricanRepublic:           "Lingala Central African Republic (ln-CF)",
		SubLangLingalaCongo:                            "Lingala Congo (ln-CG)",
		SubLangLingalaCongoDrc:                         "Lingala Congo Drc (ln-CD)",
		SubLangLithuanianLithuania:                     "Lithuanian Lithuania (lt-LT)",
		SubLangLowGermanGermany:                        "Low German Germany (nds-DE)",
		SubLangLowGermanNetherlands:                    "Low German Netherlands (nds-NL)",
		SubLangLowerSorbianGermany:                     "Lower Sorbian Germany (dsb-DE)",
		SubLangLubaKatangaCongoDrc:                     "Luba-Katanga Congo Drc (lu-CD)",
		SubLangLuoKenya:                                "Luo Kenya (luo-KE)",
		SubLangLuxembourgishLuxembourg:                 "Luxembourgish Luxembourg (lb-LU)",
		SubLangLuyiaKenya:                              "Luyia Kenya (luy-KE)",
		SubLangMacedonianNorthMacedonia:                "Macedonian North Macedonia (mk-MK)",
		SubLangMachameTanzania:                         "Machame Tanzania (jmc-TZ)",
		SubLangMakhuwaMeettoMozambique:                 "Makhuwa-Meetto Mozambique (mgh-MZ)",
		SubLangMakondeTanzania:                         "Makonde Tanzania (kde-TZ)",
		SubLangMalagasyMadagascar:                      "Malagasy Madagascar (mg-MG)",
		SubLangMalayBruneiDarussalam:                   "Malay Brunei Darussalam (ms-BN)",
		SubLangMalayMalaysia:                           "Malay Malaysia (ms-MY)",
		SubLangMalayalamIndia:                          "Malayalam India (ml-IN)",
		SubLangMalteseMalta:                            "Maltese Malta (mt-MT)",
		SubLangManxIsleOfMan:                           "Manx Isle Of Man (gv-IM)",
		SubLangMaoriNewZealand:                         "Maori New Zealand (mi-NZ)",
		SubLangMapudungunChile:                         "Mapudungun Chile (arn-CL)",
		SubLangMarathiIndia:                            "Marathi India (mr-IN)",
		SubLangMasaiKenya:                              "Masai Kenya (mas-KE)",
		SubLangMasaiTanzania:                           "Masai Tanzania (mas-TZ)",
		SubLangMazanderaniIran:                         "Mazanderani Iran (mzn-IR)",
		SubLangMeruKenya:                               "Meru Kenya (mer-KE)",
		SubLangMetaCameroon:                            "Meta' Cameroon (mgo-CM)",
		SubLangMohawkCanada:                            "Mohawk Canada (moh-CA)",
		SubLangMongolianCyrillic:                       "Mongolian (Cyrillic) (mn-Cyrl)",
		SubLangMongolianCyrillicMongolia:               "Mongolian (Cyrillic) Mongolia (mn-MN)",
		SubLangMongolianTraditionalmongolian:           "Mongolian (Traditional mongolian) (mn-Mong)",
		SubLangMongolianTraditionalmongolianPeoplesRepublicOfChina: "Mongolian (Traditional mongolian) People's Republic Of China (mn-MongCN)",
		SubLangMongolianTraditionalmongolianMongolia:               "Mongolian (Traditional mongolian) Mongolia (mn-MongMN)",
		SubLangMorisyenMauritius:                                   "Morisyen Mauritius (mfe-MU)",
		SubLangMundangCameroon:                                     "Mundang Cameroon (mua-CM)",
		SubLangNkoGuinea:                                           "N'ko Guinea (nqo-GN)",
		SubLangNamaNamibia:                                         "Nama Namibia (naq-NA)",
		SubLangNepaliIndia:                                         "Nepali India (ne-IN)",
		SubLangNepaliNepal:                                         "Nepali Nepal (ne-NP)",
		SubLangNgiemboonCameroon:                                   "Ngiemboon Cameroon (nnh-CM)",
		SubLangNgombaCameroon:                                      "Ngomba Cameroon (jgo-CM)",
		SubLangNorthernLuriIraq:                                    "Northern Luri Iraq (lrc-IQ)",
		SubLangNorthernLuriIran:                                    "Northern Luri Iran (lrc-IR)",
		SubLangNorthNdebeleZimbabwe:                                "North Ndebele Zimbabwe (nd-ZW)",
		SubLangNorwegianBokmalNorway:                               "Norwegian (Bokmal) Norway (nb-NO)",
		SubLangNorwegianNynorskNorway:                              "Norwegian (Nynorsk) Norway (nn-NO)",
		SubLangNorwegianBokmålSvalbardAndJanMayen:                  "Norwegian Bokmål Svalbard And Jan Mayen (nb-SJ)",
		SubLangNuerSudan:                                           "Nuer Sudan (nus-SD)",
		SubLangNuerSouthSudan:                                      "Nuer South Sudan (nus-SS)",
		SubLangNyankoleUganda:                                      "Nyankole Uganda (nyn-UG)",
		SubLangOccitanFrance:                                       "Occitan France (oc-FR)",
		SubLangOdiaIndia:                                           "Odia India (or-IN)",
		SubLangOromoEthiopia:                                       "Oromo Ethiopia (om-ET)",
		SubLangOromoKenya:                                          "Oromo Kenya (om-KE)",
		SubLangOssetianCyrillicGeorgia:                             "Ossetian Cyrillic, Georgia (os-GE)",
		SubLangOssetianCyrillicRussia:                              "Ossetian Cyrillic, Russia (os-RU)",
		SubLangPashtoAfghanistan:                                   "Pashto Afghanistan (ps-AF)",
		SubLangPashtoPakistan:                                      "Pashto Pakistan (ps-PK)",
		SubLangPersianAfghanistan:                                  "Persian Afghanistan (fa-AF)",
		SubLangPersianIran:                                         "Persian Iran (fa-IR)",
		SubLangPolishPoland:                                        "Polish Poland (pl-PL)",
		SubLangPortugueseAngola:                                    "Portuguese Angola (pt-AO)",
		SubLangPortugueseBrazil:                                    "Portuguese Brazil (pt-BR)",
		SubLangPortugueseCaboVerde:                                 "Portuguese Cabo Verde (pt-CV)",
		SubLangPortugueseEquatorialGuinea:                          "Portuguese Equatorial Guinea (pt-GQ)",
		SubLangPortugueseGuineaBissau:                              "Portuguese Guinea-Bissau (pt-GW)",
		SubLangPortugueseLuxembourg:                                "Portuguese Luxembourg (pt-LU)",
		SubLangPortugueseMacaoSar:                                  "Portuguese Macao Sar (pt-MO)",
		SubLangPortugueseMozambique:                                "Portuguese Mozambique (pt-MZ)",
		SubLangPortuguesePortugal:                                  "Portuguese Portugal (pt-PT)",
		SubLangPortugueseSãoToméAndPríncipe:                        "Portuguese São Tomé And Príncipe (pt-ST)",
		SubLangPortugueseSwitzerland:                               "Portuguese Switzerland (pt-CH)",
		SubLangPortugueseTimorLeste:                                "Portuguese Timor-Leste (pt-TL)",
		SubLangPrussian:                                            "Prussian (prg-001)",
		SubLangPseudoLanguagePseudoLocaleForEastAsiancomplexScriptLocalizationTesting: "Pseudo Language Pseudo Locale For East Asian/complex Script Localization Testing (qps-ploca)",
		SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTesting:                   "Pseudo Language Pseudo Locale Used For Localization Testing (qps-ploc)",
		SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTestingOfMirroredLocales:  "Pseudo Language Pseudo Locale Used For Localization Testing Of Mirrored Locales (qps-plocm)",
		SubLangPunjabi:                                  "Punjabi (pa-Arab)",
		SubLangPunjabiIndia:                             "Punjabi India (pa-IN)",
		SubLangPunjabiIslamicRepublicOfPakistan:         "Punjabi Islamic Republic Of Pakistan (pa-Arab-PK)",
		SubLangQuechuaBolivia:                           "Quechua Bolivia (quz-BO)",
		SubLangQuechuaEcuador:                           "Quechua Ecuador (quz-EC)",
		SubLangQuechuaPeru:                              "Quechua Peru (quz-PE)",
		SubLangRipuarianGermany:                         "Ripuarian Germany (ksh-DE)",
		SubLangRomanianMoldova:                          "Romanian Moldova (ro-MD)",
		SubLangRomanianRomania:                          "Romanian Romania (ro-RO)",
		SubLangRomanshSwitzerland:                       "Romansh Switzerland (rm-CH)",
		SubLangRomboTanzania:                            "Rombo Tanzania (rof-TZ)",
		SubLangRundiBurundi:                             "Rundi Burundi (rn-BI)",
		SubLangRussianBelarus:                           "Russian Belarus (ru-BY)",
		SubLangRussianKazakhstan:                        "Russian Kazakhstan (ru-KZ)",
		SubLangRussianKyrgyzstan:                        "Russian Kyrgyzstan (ru-KG)",
		SubLangRussianMoldova:                           "Russian Moldova (ru-MD)",
		SubLangRussianRussia:                            "Russian Russia (ru-RU)",
		SubLangRussianUkraine:                           "Russian Ukraine (ru-UA)",
		SubLangRwaTanzania:                              "Rwa Tanzania (rwk-TZ)",
		SubLangSahoEritrea:                              "Saho Eritrea (ssy-ER)",
		SubLangSakhaRussia:                              "Sakha Russia (sah-RU)",
		SubLangSamburuKenya:                             "Samburu Kenya (saq-KE)",
		SubLangSamiInariFinland:                         "Sami (Inari) Finland (smn-FI)",
		SubLangSamiLuleNorway:                           "Sami (Lule) Norway (smj-NO)",
		SubLangSamiLuleSweden:                           "Sami (Lule) Sweden (smj-SE)",
		SubLangSamiNorthernFinland:                      "Sami (Northern) Finland (se-FI)",
		SubLangSamiNorthernNorway:                       "Sami (Northern) Norway (se-NO)",
		SubLangSamiNorthernSweden:                       "Sami (Northern) Sweden (se-SE)",
		SubLangSamiSkoltFinland:                         "Sami (Skolt) Finland (sms-FI)",
		SubLangSamiSouthernNorway:                       "Sami (Southern) Norway (sma-NO)",
		SubLangSamiSouthernSweden:                       "Sami (Southern) Sweden (sma-SE)",
		SubLangSangoCentralAfricanRepublic:              "Sango Central African Republic (sg-CF)",
		SubLangSanguTanzania:                            "Sangu Tanzania (sbp-TZ)",
		SubLangSanskritIndia:                            "Sanskrit India (sa-IN)",
		SubLangScottishGaelicUnitedKingdom:              "Scottish Gaelic United Kingdom (gd-GB)",
		SubLangSenaMozambique:                           "Sena Mozambique (seh-MZ)",
		SubLangSerbianCyrillic:                          "Serbian (Cyrillic) (sr-Cyrl)",
		SubLangSerbianCyrillicBosniaAndHerzegovina:      "Serbian (Cyrillic) Bosnia And Herzegovina (sr-Cyrl-BA)",
		SubLangSerbianCyrillicMontenegro:                "Serbian (Cyrillic) Montenegro (sr-Cyrl-ME)",
		SubLangSerbianCyrillicSerbia:                    "Serbian (Cyrillic) Serbia (sr-Cyrl-RS)",
		SubLangSerbianCyrillicSerbiaAndMontenegroformer: "Serbian (Cyrillic) Serbia And Montenegro (former) (sr-Cyrl-CS)",
		SubLangSerbianLatin:                             "Serbian (Latin) (sr-Latn)",
		SubLangSerbianLatinBosniaAndHerzegovina:         "Serbian (Latin) Bosnia And Herzegovina (sr-Latn-BA)",
		SubLangSerbianLatinMontenegro:                   "Serbian (Latin) Montenegro (sr-Latn-ME)",
		SubLangSerbianLatinSerbia:                       "Serbian (Latin) Serbia (sr-Latn-RS)",
		SubLangSerbianLatinSerbiaAndMontenegroformer:    "Serbian (Latin) Serbia And Montenegro (former) (sr-Latn-CS)",
		SubLangSesothoSaLeboaSouthAfrica:                "Sesotho Sa Leboa South Africa (nso-ZA)",
		SubLangSetswanaBotswana:                         "Setswana Botswana (tn-BW)",
		SubLangSetswanaSouthAfrica:                      "Setswana South Africa (tn-ZA)",
		SubLangShambalaTanzania:                         "Shambala Tanzania (ksb-TZ)",
		SubLangShonaLatin:                               "Shona Latin (sn-Latn)",
		SubLangShonaZimbabwe:                            "Shona Zimbabwe (sn-Latn-ZW)",
		SubLangSindhi:                                   "Sindhi (sd-Arab)",
		SubLangSindhiIslamicRepublicOfPakistan:          "Sindhi Islamic Republic Of Pakistan (sd-Arab-PK)",
		SubLangSinhalaSriLanka:                          "Sinhala Sri Lanka (si-LK)",
		SubLangSlovakSlovakia:                           "Slovak Slovakia (sk-SK)",
		SubLangSlovenianSlovenia:                        "Slovenian Slovenia (sl-SI)",
		SubLangSogaUganda:                               "Soga Uganda (xog-UG)",
		SubLangSomaliDjibouti:                           "Somali Djibouti (so-DJ)",
		SubLangSomaliEthiopia:                           "Somali Ethiopia (so-ET)",
		SubLangSomaliKenya:                              "Somali Kenya (so-KE)",
		SubLangSomaliSomalia:                            "Somali Somalia (so-SO)",
		SubLangSothoSouthAfrica:                         "Sotho South Africa (st-ZA)",
		SubLangSouthNdebeleSouthAfrica:                  "South Ndebele South Africa (nr-ZA)",
		SubLangSouthernSothoLesotho:                     "Southern Sotho Lesotho (st-LS)",
		SubLangSpanishArgentina:                         "Spanish Argentina (es-AR)",
		SubLangSpanishBelize:                            "Spanish Belize (es-BZ)",
		SubLangSpanishBolivarianRepublicOfVenezuela:     "Spanish Bolivarian Republic Of Venezuela (es-VE)",
		SubLangSpanishBolivia:                           "Spanish Bolivia (es-BO)",
		SubLangSpanishBrazil:                            "Spanish Brazil (es-BR)",
		SubLangSpanishChile:                             "Spanish Chile (es-CL)",
		SubLangSpanishColombia:                          "Spanish Colombia (es-CO)",
		SubLangSpanishCostaRica:                         "Spanish Costa Rica (es-CR)",
		SubLangSpanishCuba:                              "Spanish Cuba (es-CU)",
		SubLangSpanishDominicanRepublic:                 "Spanish Dominican Republic (es-DO)",
		SubLangSpanishEcuador:                           "Spanish Ecuador (es-EC)",
		SubLangSpanishElSalvador:                        "Spanish El Salvador (es-SV)",
		SubLangSpanishEquatorialGuinea:                  "Spanish Equatorial Guinea (es-GQ)",
		SubLangSpanishGuatemala:                         "Spanish Guatemala (es-GT)",
		SubLangSpanishHonduras:                          "Spanish Honduras (es-HN)",
		SubLangSpanishLatinAmerica:                      "Spanish Latin America (es-419)",
		SubLangSpanishMexico:                            "Spanish Mexico (es-MX)",
		SubLangSpanishNicaragua:                         "Spanish Nicaragua (es-NI)",
		SubLangSpanishPanama:                            "Spanish Panama (es-PA)",
		SubLangSpanishParaguay:                          "Spanish Paraguay (es-PY)",
		SubLangSpanishPeru:                              "Spanish Peru (es-PE)",
		SubLangSpanishPhilippines:                       "Spanish Philippines (es-PH)",
		SubLangSpanishPuertoRico:                        "Spanish Puerto Rico (es-PR)",
		SubLangSpanishSpain:                             "Spanish Spain (es-ES_tradnl)",
		SubLangSpanishSpain:                             "Spanish Spain (es-ES)",
		SubLangSpanishUnitedStates:                      "Spanish United States (es-US)",
		SubLangSpanishUruguay:                           "Spanish Uruguay (es-UY)",
		SubLangStandardMoroccanTamazightMorocco:         "Standard Moroccan Tamazight Morocco (zgh-Tfng-MA)",
		SubLangStandardMoroccanTamazightTifinagh:        "Standard Moroccan Tamazight Tifinagh (zgh-Tfng)",
		SubLangSwatiSouthAfrica:                         "Swati South Africa (ss-ZA)",
		SubLangSwatiSwaziland:                           "Swati Swaziland (ss-SZ)",
		SubLangSwedishÅlandIslands:                      "Swedish Åland Islands (sv-AX)",
		SubLangSwedishFinland:                           "Swedish Finland (sv-FI)",
		SubLangSwedishSweden:                            "Swedish Sweden (sv-SE)",
		SubLangSyriacSyria:                              "Syriac Syria (syr-SY)",
		SubLangTachelhitTifinagh:                        "Tachelhit Tifinagh (shi-Tfng)",
		SubLangTachelhitTifinaghMorocco:                 "Tachelhit Tifinagh, Morocco (shi-Tfng-MA)",
		SubLangTachelhitLatin:                           "Tachelhit (Latin) (shi-Latn)",
		SubLangTachelhitLatinMorocco:                    "Tachelhit (Latin) Morocco (shi-Latn-MA)",
		SubLangTaitaKenya:                               "Taita Kenya (dav-KE)",
		SubLangTajikCyrillic:                            "Tajik (Cyrillic) (tg-Cyrl)",
		SubLangTajikCyrillicTajikistan:                  "Tajik (Cyrillic) Tajikistan (tg-Cyrl-TJ)",
		SubLangTamazightLatin:                           "Tamazight (Latin) (tzm-Latn)",
		SubLangTamazightLatinAlgeria:                    "Tamazight (Latin) Algeria (tzm-Latn-DZ)",
		SubLangTamilIndia:                               "Tamil India (ta-IN)",
		SubLangTamilMalaysia:                            "Tamil Malaysia (ta-MY)",
		SubLangTamilSingapore:                           "Tamil Singapore (ta-SG)",
		SubLangTamilSriLanka:                            "Tamil Sri Lanka (ta-LK)",
		SubLangTasawaqNiger:                             "Tasawaq Niger (twq-NE)",
		SubLangTatarRussia:                              "Tatar Russia (tt-RU)",
		SubLangTeluguIndia:                              "Telugu India (te-IN)",
		SubLangTesoKenya:                                "Teso Kenya (teo-KE)",
		SubLangTesoUganda:                               "Teso Uganda (teo-UG)",
		SubLangThaiThailand:                             "Thai Thailand (th-TH)",
		SubLangTibetanIndia:                             "Tibetan India (bo-IN)",
		SubLangTibetanPeoplesRepublicOfChina:            "Tibetan People's Republic Of China (bo-CN)",
		SubLangTigreEritrea:                             "Tigre Eritrea (tig-ER)",
		SubLangTigrinyaEritrea:                          "Tigrinya Eritrea (ti-ER)",
		SubLangTigrinyaEthiopia:                         "Tigrinya Ethiopia (ti-ET)",
		SubLangTonganTonga:                              "Tongan Tonga (to-TO)",
		SubLangTsongaSouthAfrica:                        "Tsonga South Africa (ts-ZA)",
		SubLangTurkishCyprus:                            "Turkish Cyprus (tr-CY)",
		SubLangTurkishTurkey:                            "Turkish Turkey (tr-TR)",
		SubLangTurkmenTurkmenistan:                      "Turkmen Turkmenistan (tk-TM)",
		SubLangUkrainianUkraine:                         "Ukrainian Ukraine (uk-UA)",
		SubLangUpperSorbianGermany:                      "Upper Sorbian Germany (hsb-DE)",
		SubLangUrduIndia:                                "Urdu India (ur-IN)",
		SubLangUrduIslamicRepublicOfPakistan:            "Urdu Islamic Republic Of Pakistan (ur-PK)",
		SubLangUyghurPeoplesRepublicOfChina:             "Uyghur People's Republic Of China (ug-CN)",
		SubLangUzbekPersoArabic:                         "Uzbek Perso-Arabic (uz-Arab)",
		SubLangUzbekPersoArabicAfghanistan:              "Uzbek Perso-Arabic, Afghanistan (uz-Arab-AF)",
		SubLangUzbekCyrillic:                            "Uzbek (Cyrillic) (uz-Cyrl)",
		SubLangUzbekCyrillicUzbekistan:                  "Uzbek (Cyrillic) Uzbekistan (uz-Cyrl-UZ)",
		SubLangUzbekLatin:                               "Uzbek (Latin) (uz-Latn)",
		SubLangUzbekLatinUzbekistan:                     "Uzbek (Latin) Uzbekistan (uz-Latn-UZ)",
		SubLangVai:                                      "Vai (vai-Vaii)",
		SubLangVaiLiberia:                               "Vai Liberia (vai-Vaii-LR)",
		SubLangVaiLatinLiberia:                          "Vai (Latin) Liberia (vai-Latn-LR)",
		SubLangVaiLatin:                                 "Vai (Latin) (vai-Latn)",
		SubLangValencianSpain:                           "Valencian Spain (ca-ESvalencia)",
		SubLangVendaSouthAfrica:                         "Venda South Africa (ve-ZA)",
		SubLangVietnameseVietnam:                        "Vietnamese Vietnam (vi-VN)",
		SubLangVolapükWorld:                             "Volapük World (vo-001)",
		SubLangVunjoTanzania:                            "Vunjo Tanzania (vun-TZ)",
		SubLangWalserSwitzerland:                        "Walser Switzerland (wae-CH)",
		SubLangWelshUnitedKingdom:                       "Welsh United Kingdom (cy-GB)",
		SubLangWolayttaEthiopia:                         "Wolaytta Ethiopia (wal-ET)",
		SubLangWolofSenegal:                             "Wolof Senegal (wo-SN)",
		SubLangXhosaSouthAfrica:                         "Xhosa South Africa (xh-ZA)",
		SubLangYangbenCameroon:                          "Yangben Cameroon (yav-CM)",
		SubLangYiPeoplesRepublicOfChina:                 "Yi People's Republic Of China (ii-CN)",
		SubLangYiddishWorld:                             "Yiddish World (yi-001)",
		SubLangYorubaBenin:                              "Yoruba Benin (yo-BJ)",
		SubLangYorubaNigeria:                            "Yoruba Nigeria (yo-NG)",
		SubLangZarmaNiger:                               "Zarma Niger (dje-NE)",
		SubLangZuluSouthAfrica:                          "Zulu South Africa (zu-ZA)",
	}

	if val, ok := rsrcSubLangMap[subLang]; ok {
		return val
	}

	return "?"
}

// PrettyResourceLang prettifies the resource lang and sub lang.
func PrettyResourceLang(lang ResourceLang, subLang int) string {
	m := map[ResourceLang]map[int]ResourceSubLang{
		LangArabic: {
			0x05: SubLangArabicAlgeria,
			0x0f: SubLangArabicBahrain,
			0x03: SubLangArabicEgypt,
			0x02: SubLangArabicIraq,
			0x0B: SubLangArabicJordan,
			0x0D: SubLangArabicKuwait,
			0x0C: SubLangArabicLebanon,
			0x04: SubLangArabicLibya,
			0x06: SubLangArabicMorocco,
			0x08: SubLangArabicOman,
			0x10: SubLangArabicQatar,
			0x01: SubLangArabicSaudiArabia,
			0x0A: SubLangArabicSyria,
			0x07: SubLangArabicTunisia,
			0x0E: SubLangArabicUae,
			0x09: SubLangArabicYemen,
		},
		LangAzeri: {
			0x02: SubLangAzeriCyrillic,
			0x01: SubLangAzeriLatin,
		},
		LangBangla: {
			0x02: SubLangBanglaBangladesh,
			0x01: SubLangBanglaIndia,
		},
		LangBosnian: {
			0x08: SubLangBosnianBosniaHerzegovinaCyrillic,
			0x05: SubLangBosnianBosniaHerzegovinaLatin,
		},
		LangChinese: {
			0x03: SubLangChineseHongkong,
			0x05: SubLangChineseMacau,
			0x04: SubLangChineseSingapore,
			0x02: SubLangChineseSimplified,
		},
		LangCroatian: {
			0x04: SubLangCroatianBosniaHerzegovinaLatin,
			0x01: SubLangCroatianCroatia,
		},
		LangDutch: {
			0x02: SubLangDutchBelgian,
			0x01: SubLangDutch,
		},
	}
	return m[lang][subLang].String()
}

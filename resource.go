// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

// ResourceType represents a resource type.
type ResourceType int

// ResourceLang represents a resource language.
type ResourceLang int

// ResourceSubLang represents a resource sub language.
type ResourceSubLang int

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

// Predefined Resource Languages.
const (
	LangNeutral       ResourceLang = iota
	LangInvariant                  = 0x7f
	LangAfrikaans                  = 0x36
	LangAlbanian                   = 0x1c
	LangArabic                     = 0x01
	LangArmenian                   = 0x2b
	LangAssamese                   = 0x4d
	LangAzeri                      = 0x2c
	LangBasque                     = 0x2d
	LangBelarusian                 = 0x23
	LangBangla                     = 0x45
	LangBulgarian                  = 0x02
	LangCatalan                    = 0x03
	LangChinese                    = 0x04
	LangCroatian                   = 0x1a
	LangBosnian                    = 0x1a
	LangCzech                      = 0x05
	LangDanish                     = 0x06
	LangDivehi                     = 0x65
	LangDutch                      = 0x13
	LangEnglish                    = 0x09
	LangEstonian                   = 0x25
	LangFaeroese                   = 0x38
	LangFarsi                      = 0x29
	LangFinnish                    = 0x0b
	LangFrench                     = 0x0c
	LangGalician                   = 0x56
	LangGeorgian                   = 0x37
	LangGerman                     = 0x07
	LangGreek                      = 0x08
	LangGujarati                   = 0x47
	LangHebrew                     = 0x0d
	LangHindi                      = 0x39
	LangHungarian                  = 0x0e
	LangIcelandic                  = 0x0f
	LangIndonesian                 = 0x21
	LangItalian                    = 0x10
	LangJapanese                   = 0x11
	LangKannada                    = 0x4b
	LangKashmiri                   = 0x60
	LangKazak                      = 0x3f
	LangKonkani                    = 0x57
	LangKorean                     = 0x12
	LangKyrgyz                     = 0x40
	LangLatvian                    = 0x26
	LangLithuanian                 = 0x27
	LangMacedonian                 = 0x2f
	LangMalay                      = 0x3e
	LangMalayalam                  = 0x4c
	LangManipuri                   = 0x58
	LangMarathi                    = 0x4e
	LangMongolian                  = 0x50
	LangNepali                     = 0x61
	LangNorwegian                  = 0x14
	LangOriya                      = 0x48
	LangPolish                     = 0x15
	LangPortuguese                 = 0x16
	LangPunjabi                    = 0x46
	LangRomanian                   = 0x18
	LangRussian                    = 0x19
	LangSanskrit                   = 0x4f
	LangSerbian                    = 0x1a
	LangSindhi                     = 0x59
	LangSlovak                     = 0x1b
	LangSlovenian                  = 0x24
	LangSpanish                    = 0x0a
	LangSwahili                    = 0x41
	LangSwedish                    = 0x1d
	LangSyriac                     = 0x5a
	LangTamil                      = 0x49
	LangTatar                      = 0x44
	LangTelugu                     = 0x4a
	LangThai                       = 0x1e
	LangTurkish                    = 0x1f
	LangUkrainian                  = 0x22
	LangUrdu                       = 0x20
	LangUzbek                      = 0x43
	LangVietnamese                 = 0x2a
	LangGaelic                     = 0x3c
	LangMaltese                    = 0x3a
	LangMaori                      = 0x28
	LangRhaetoRomance              = 0x17
	LangSami                       = 0x3b
	LangSorbian                    = 0x2e
	LangSutu                       = 0x30
	LangTsonga                     = 0x31
	LangTswana                     = 0x32
	LangVenda                      = 0x33
	LangXhosa                      = 0x34
	LangZulu                       = 0x35
	LangEsperanto                  = 0x8f
	LangWalon                      = 0x90
	LangCornish                    = 0x91
	LangWelsh                      = 0x92
	LangBreton                     = 0x93
	LangInuktitut                  = 0x5d
	LangIrish                      = 0x3C
	LangLowerSorbian               = 0x2E
	LangPular                      = 0x67
	LangQuechua                    = 0x6B
	LangTamazight                  = 0x5F
	LangTigrinya                   = 0x73
	LangValencian                  = 0x03
)

// Predefined Resource Sub languages.
const (
	SubLangAfrikaansSouthAfrica ResourceSubLang = iota
	SubLangAlbanianAlbania
	SubLangAlsatianFrance
	SubLangAmharicEthiopia
	SubLangArabicAlgeria
	SubLangArabicBahrain
	SubLangArabicEgypt
	SubLangArabicIraq
	SubLangArabicJordan
	SubLangArabicKuwait
	SubLangArabicLebanon
	SubLangArabicLibya
	SubLangArabicMorocco
	SubLangArabicOman
	SubLangArabicQatar
	SubLangArabicSaudiArabia
	SubLangArabicSyria
	SubLangArabicTunisia
	SubLangArabicUae
	SubLangArabicYemen
	SubLangArmenianArmenia
	SubLangAssameseIndia
	SubLangAzeriCyrillic
	SubLangAzeriLatin
	SubLangBashkirRussia
	SubLangBasqueBasque
	SubLangBelarusianBelarus
	SubLangBanglaBangladesh
	SubLangBanglaIndia
	SubLangBosnianBosniaHerzegovinaCyrillic
	SubLangBosnianBosniaHerzegovinaLatin
	SubLangBretonFrance
	SubLangBulgarianBulgaria
	SubLangCatalanCatalan
	SubLangChineseHongkong
	SubLangChineseMacau
	SubLangChineseSimplified
	SubLangChineseSingapore
	SubLangChineseTraditional
	SubLangCorsicanFrance
	SubLangCroatianBosniaHerzegovinaLatin
	SubLangCroatianCroatia
	SubLangCustomDefault
	SubLangCustomUnspecified
	SubLangCzechCzechRepublic
	SubLangDanishDenmark
	SubLangDariAfghanistan
	SubLangDefault
	SubLangDivehiMaldives
	SubLangDutchBelgian
	SubLangDutch
	SubLangEnglishAus
	SubLangEnglishBelize
	SubLangEnglishCan
	SubLangEnglishCaribbean
	SubLangEnglishEire
	SubLangEnglishIndia
	SubLangEnglishJamaica
	SubLangEnglishMalaysia
	SubLangEnglishNz
	SubLangEnglishPhilippines
	SubLangEnglishSingapore
	SubLangEnglishSouthAfrica
	SubLangEnglishTrinidad
	SubLangEnglishUk
	SubLangEnglishUs
	SubLangEnglishZimbabwe
	SubLangEnglishIreland
	SubLangEstonianEstonia
	SubLangFaeroeseFaroeIslands
	SubLangFilipinoPhilippines
	SubLangFinnishFinland
	SubLangFrenchBelgian
	SubLangFrenchCanadian
	SubLangFrenchLuxembourg
	SubLangFrenchMonaco
	SubLangFrenchSwiss
	SubLangFrench
	SubLangFrisianNetherlands
	SubLangGalicianGalician
	SubLangGeorgianGeorgia
	SubLangGermanAustrian
	SubLangGermanLiechtenstein
	SubLangGermanLuxembourg
	SubLangGermanSwiss
	SubLangGerman
	SubLangGreekGreece
	SubLangGreenlandicGreenland
	SubLangGujaratiIndia
	SubLangHausaNigeriaLatin
	SubLangHebrewIsrael
	SubLangHindiIndia
	SubLangHungarianHungary
	SubLangIcelandicIceland
	SubLangIgboNigeria
	SubLangIndonesianIndonesia
	SubLangInuktitutCanadaLatin
	SubLangInuktitutCanada
	SubLangIrishIreland
	SubLangItalianSwiss
	SubLangItalian
	SubLangJapaneseJapan
	SubLangKannadaIndia
	SubLangKashmiriIndia
	SubLangKashmiriSasia
	SubLangKazakKazakhstan
	SubLangKhmerCambodia
	SubLangKicheGuatemala
	SubLangKinyarwandaRwanda
	SubLangKonkaniIndia
	SubLangKorean
	SubLangKyrgyzKyrgyzstan
	SubLangLaoLao
	SubLangLatvianLatvia
	SubLangLithuanianClassic
	SubLangLithuanian
	SubLangLowerSorbianGermany
	SubLangLuxembourgishLuxembourg
	SubLangMacedonianMacedonia
	SubLangMalayBruneiDarussalam
	SubLangMalayMalaysia
	SubLangMalayalamIndia
	SubLangMalteseMalta
	SubLangMaoriNewZealand
	SubLangMapudungunChile
	SubLangMarathiIndia
	SubLangMohawkMohawk
	SubLangMongolianCyrillicMongolia
	SubLangMongolianPrc
	SubLangNepaliIndia
	SubLangNepaliNepal
	SubLangNeutral
	SubLangNorwegianBokmal
	SubLangNorwegianNynorsk
	SubLangOccitanFrance
	SubLangOriyaIndia
	SubLangPashtoAfghanistan
	SubLangPersianIran
	SubLangPolishPoland
	SubLangPortugueseBrazilian
	SubLangPortuguese
	SubLangPunjabiIndia
	SubLangQuechuaBolivia
	SubLangQuechuaEcuador
	SubLangQuechuaPeru
	SubLangRomanianRomania
	SubLangRomanshSwitzerland
	SubLangRussianRussia
	SubLangSamiInariFinland
	SubLangSamiLuleNorway
	SubLangSamiLuleSweden
	SubLangSamiNorthernFinland
	SubLangSamiNorthernNorway
	SubLangSamiNorthernSweden
	SubLangSamiSkoltFinland
	SubLangSamiSouthernNorway
	SubLangSamiSouthernSweden
	SubLangSanskritIndia
	SubLangSerbianBosniaHerzegovinaCyrillic
	SubLangSerbianBosniaHerzegovinaLatin
	SubLangSerbianCroatia
	SubLangSerbianCyrillic
	SubLangSerbianLatin
	SubLangSindhiAfghanistan
	SubLangSindhiIndia
	SubLangSindhiPakistan
	SubLangSinhaleseSriLanka
	SubLangSlovakSlovakia
	SubLangSlovenianSlovenia
	SubLangSothoNorthernSouthAfrica
	SubLangSpanishArgentina
	SubLangSpanishBolivia
	SubLangSpanishChile
	SubLangSpanishColombia
	SubLangSpanishCostaRica
	SubLangSpanishDominicanRepublic
	SubLangSpanishEcuador
	SubLangSpanishElSalvador
	SubLangSpanishGuatemala
	SubLangSpanishHonduras
	SubLangSpanishMexican
	SubLangSpanishModern
	SubLangSpanishNicaragua
	SubLangSpanishPanama
	SubLangSpanishParaguay
	SubLangSpanishPeru
	SubLangSpanishPuertoRico
	SubLangSpanishUruguay
	SubLangSpanishUs
	SubLangSpanishVenezuela
	SubLangSpanish
	SubLangSwahiliKenya
	SubLangSwedishFinland
	SubLangSwedish
	SubLangSyriacSyria
	SubLangSysDefault
	SubLangTajikTajikistan
	SubLangTamazightAlgeriaLatin
	SubLangTamilIndia
	SubLangTatarRussia
	SubLangTeluguIndia
	SubLangThaiThailand
	SubLangTibetanPrc
	SubLangTigrignaEritrea
	SubLangTswanaSouthAfrica
	SubLangTurkishTurkey
	SubLangTurkmenTurkmenistan
	SubLangUiCustomDefault
	SubLangUighurPrc
	SubLangUkrainianUkraine
	SubLangUpperSorbianGermany
	SubLangUrduIndia
	SubLangUrduPakistan
	SubLangUzbekCyrillic
	SubLangUzbekLatin
	SubLangVietnameseVietnam
	SubLangWelshUnitedKingdom
	SubLangWolofSenegal
	SubLangXhosaSouthAfrica
	SubLangYakutRussia
	SubLangYiPrc
	SubLangYorubaNigeria
	SubLangZuluSouthAfrica
	SubLangPularSenegal
	SubLangPunjabiPakistan
	SubLangTswanaBotswana
	SubLangTamilSriLanka
	SubLangTigrinyaEthiopia
	SubLangTigrinyaEritrea
	SubLangValencianValencia
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
	Lang uint32 `json:"lang"`

	// Sub language ID.
	SubLang uint32 `json:"sub_lang"`
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
				Lang:    res.Name & 0x3ff,
				SubLang: res.Name >> 10,
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

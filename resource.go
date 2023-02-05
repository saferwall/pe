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

// String stringify the resource language.
func (rl ResourceLang) String() string {

	rsrcLangMap := map[ResourceLang]string{
		LangNeutral:       "Neutral",
		LangInvariant:     "Invariant",
		LangAfrikaans:     "Afrikaans",
		LangAlbanian:      "Albanian",
		LangArabic:        "Arabic",
		LangArmenian:      "Armenian",
		LangAssamese:      "Assamese",
		LangAzeri:         "Azeri",
		LangBasque:        "Basque",
		LangBelarusian:    "Belarusian",
		LangBangla:        "Bangla",
		LangBulgarian:     "Bulgarian",
		LangCatalan:       "Catalan", // Same as LangValencian.
		LangChinese:       "Chinese",
		LangCroatian:      "Croatian", // Same as LangBosnian and LangSerbian.
		LangCzech:         "Czech",
		LangDanish:        "Danish",
		LangDivehi:        "Divehi",
		LangDutch:         "Dutch",
		LangEnglish:       "English",
		LangEstonian:      "Estonian",
		LangFaeroese:      "Faeroese",
		LangFarsi:         "Farsi",
		LangFinnish:       "Finnish",
		LangFrench:        "French",
		LangGalician:      "Galician",
		LangGeorgian:      "Georgian",
		LangGerman:        "German",
		LangGreek:         "Greek",
		LangGujarati:      "Gujarati",
		LangHebrew:        "Hebrew",
		LangHindi:         "Hindi",
		LangHungarian:     "Hungarian",
		LangIcelandic:     "Icelandic",
		LangIndonesian:    "Indonesian",
		LangItalian:       "Italian",
		LangJapanese:      "Japanese",
		LangKannada:       "Kannada",
		LangKashmiri:      "Kashmiri",
		LangKazak:         "Kazak",
		LangKonkani:       "Konkani",
		LangKorean:        "Korean",
		LangKyrgyz:        "Kyrgyz",
		LangLatvian:       "Latvian",
		LangLithuanian:    "Lithuanian",
		LangMacedonian:    "Macedonian",
		LangMalay:         "Malay",
		LangMalayalam:     "Malayalam",
		LangManipuri:      "Manipuri",
		LangMarathi:       "Marathi",
		LangMongolian:     "Mongolian",
		LangNepali:        "Nepali",
		LangNorwegian:     "Norwegian",
		LangOriya:         "Oriya",
		LangPolish:        "Polish",
		LangPortuguese:    "Portuguese",
		LangPunjabi:       "Punjabi",
		LangRomanian:      "Romanian",
		LangRussian:       "Russian",
		LangSanskrit:      "Sanskrit",
		LangSindhi:        "Sindhi",
		LangSlovak:        "Slovak",
		LangSlovenian:     "Slovenian",
		LangSpanish:       "Spanish",
		LangSwahili:       "Swahili",
		LangSwedish:       "Swedish",
		LangSyriac:        "Syriac",
		LangTamil:         "Tamil",
		LangTatar:         "Tatar",
		LangTelugu:        "Telugu",
		LangThai:          "Thai",
		LangTurkish:       "Turkish",
		LangUkrainian:     "Ukrainian",
		LangUrdu:          "Urdu",
		LangUzbek:         "Uzbek",
		LangVietnamese:    "Vietnamese",
		LangGaelic:        "Gaelic", // Same as LangIrish.
		LangMaltese:       "Maltese",
		LangMaori:         "Maori",
		LangRhaetoRomance: "Rhaeto Romance",
		LangSami:          "Sami",
		LangSorbian:       "Sorbian", // Same as LangLowerSorbian
		LangSutu:          "Sutu",
		LangTsonga:        "Tsonga",
		LangTswana:        "Tswana",
		LangVenda:         "Venda",
		LangXhosa:         "Xhosa",
		LangZulu:          "Zulu",
		LangEsperanto:     "Esperanto",
		LangWalon:         "Walon",
		LangCornish:       "Cornish",
		LangWelsh:         "Welsh",
		LangBreton:        "Breton",
		LangInuktitut:     "Inuktitut",
		LangPular:         "Pular",
		LangQuechua:       "Quechua",
		LangTamazight:     "Tamazight",
		LangTigrinya:      "Tigrinya",
	}

	return rsrcLangMap[rl]
}

// String stringify the resource sub language.
func (rsl ResourceSubLang) String() string {

	rsrcSubLangMap := map[ResourceSubLang]string{
		SubLangAfrikaansSouthAfrica:             "Afrikaans South Africa",
		SubLangAlbanianAlbania:                  "Albanian Albania",
		SubLangAlsatianFrance:                   "Alsatian France",
		SubLangAmharicEthiopia:                  "Amharic Ethiopia",
		SubLangArabicAlgeria:                    "Arabic Algeria",
		SubLangArabicBahrain:                    "Arabic Bahrain",
		SubLangArabicEgypt:                      "Arabic Egypt",
		SubLangArabicIraq:                       "Arabic Iraq",
		SubLangArabicJordan:                     "Arabic Jordan",
		SubLangArabicKuwait:                     "Arabic Kuwait",
		SubLangArabicLebanon:                    "Arabic Lebanon",
		SubLangArabicLibya:                      "Arabic Libya",
		SubLangArabicMorocco:                    "Arabic Morocco",
		SubLangArabicOman:                       "Arabic Oman",
		SubLangArabicQatar:                      "Arabic Qatar",
		SubLangArabicSaudiArabia:                "Arabic Saudi Arabia",
		SubLangArabicSyria:                      "Arabic Syria",
		SubLangArabicTunisia:                    "Arabic Tunisia",
		SubLangArabicUae:                        "Arabic Uae",
		SubLangArabicYemen:                      "Arabic Yemen",
		SubLangArmenianArmenia:                  "Armenian Armenia",
		SubLangAssameseIndia:                    "Assamese India",
		SubLangAzeriCyrillic:                    "Azeri Cyrillic",
		SubLangAzeriLatin:                       "Azeri Latin",
		SubLangBashkirRussia:                    "Bashkir Russia",
		SubLangBasqueBasque:                     "Basque Basque",
		SubLangBelarusianBelarus:                "Belarusian Belarus",
		SubLangBanglaBangladesh:                 "Bangla Bangladesh",
		SubLangBanglaIndia:                      "Bangla India",
		SubLangBosnianBosniaHerzegovinaCyrillic: "Bosnian Bosnia Herzegovina Cyrillic",
		SubLangBosnianBosniaHerzegovinaLatin:    "Bosnian Bosnia Herzegovina Latin",
		SubLangBretonFrance:                     "Breton France",
		SubLangBulgarianBulgaria:                "Bulgarian Bulgaria",
		SubLangCatalanCatalan:                   "Catalan Catalan",
		SubLangChineseHongkong:                  "Chinese Hongkong",
		SubLangChineseMacau:                     "Chinese Macau",
		SubLangChineseSimplified:                "Chinese Simplified",
		SubLangChineseSingapore:                 "Chinese Singapore",
		SubLangChineseTraditional:               "Chinese Traditional",
		SubLangCorsicanFrance:                   "Corsican France",
		SubLangCroatianBosniaHerzegovinaLatin:   "Croatian Bosnia Herzegovina Latin",
		SubLangCroatianCroatia:                  "Croatian Croatia",
		SubLangCustomDefault:                    "Custom Default",
		SubLangCustomUnspecified:                "Custom Unspecified",
		SubLangCzechCzechRepublic:               "Czech Czech Republic",
		SubLangDanishDenmark:                    "Danish Denmark",
		SubLangDariAfghanistan:                  "Dari Afghanistan",
		SubLangDefault:                          "Default",
		SubLangDivehiMaldives:                   "Divehi Maldives",
		SubLangDutchBelgian:                     "Dutch Belgian",
		SubLangDutch:                            "Dutch",
		SubLangEnglishAus:                       "English Aus",
		SubLangEnglishBelize:                    "English Belize",
		SubLangEnglishCan:                       "English Can",
		SubLangEnglishCaribbean:                 "English Caribbean",
		SubLangEnglishEire:                      "English Eire",
		SubLangEnglishIndia:                     "English India",
		SubLangEnglishJamaica:                   "English Jamaica",
		SubLangEnglishMalaysia:                  "English Malaysia",
		SubLangEnglishNz:                        "English Nz",
		SubLangEnglishPhilippines:               "English Philippines",
		SubLangEnglishSingapore:                 "English Singapore",
		SubLangEnglishSouthAfrica:               "English South Africa",
		SubLangEnglishTrinidad:                  "English Trinidad",
		SubLangEnglishUk:                        "English Uk",
		SubLangEnglishUs:                        "English Us",
		SubLangEnglishZimbabwe:                  "English Zimbabwe",
		SubLangEnglishIreland:                   "English Ireland",
		SubLangEstonianEstonia:                  "Estonian Estonia",
		SubLangFaeroeseFaroeIslands:             "Faeroese Faroe Islands",
		SubLangFilipinoPhilippines:              "Filipino Philippines",
		SubLangFinnishFinland:                   "Finnish Finland",
		SubLangFrenchBelgian:                    "French Belgian",
		SubLangFrenchCanadian:                   "French Canadian",
		SubLangFrenchLuxembourg:                 "French Luxembourg",
		SubLangFrenchMonaco:                     "French Monaco",
		SubLangFrenchSwiss:                      "French Swiss",
		SubLangFrench:                           "French",
		SubLangFrisianNetherlands:               "Frisian Netherlands",
		SubLangGalicianGalician:                 "Galician Galician",
		SubLangGeorgianGeorgia:                  "Georgian Georgia",
		SubLangGermanAustrian:                   "German Austrian",
		SubLangGermanLiechtenstein:              "German Liechtenstein",
		SubLangGermanLuxembourg:                 "German Luxembourg",
		SubLangGermanSwiss:                      "German Swiss",
		SubLangGerman:                           "German",
		SubLangGreekGreece:                      "Greek Greece",
		SubLangGreenlandicGreenland:             "Greenlandic Greenland",
		SubLangGujaratiIndia:                    "Gujarati India",
		SubLangHausaNigeriaLatin:                "Hausa Nigeria Latin",
		SubLangHebrewIsrael:                     "Hebrew Israel",
		SubLangHindiIndia:                       "Hindi India",
		SubLangHungarianHungary:                 "Hungarian Hungary",
		SubLangIcelandicIceland:                 "Icelandic Iceland",
		SubLangIgboNigeria:                      "Igbo Nigeria",
		SubLangIndonesianIndonesia:              "Indonesian Indonesia",
		SubLangInuktitutCanadaLatin:             "Inuktitut Canada Latin",
		SubLangInuktitutCanada:                  "Inuktitut Canada",
		SubLangIrishIreland:                     "Irish Ireland",
		SubLangItalianSwiss:                     "Italian Swiss",
		SubLangItalian:                          "Italian",
		SubLangJapaneseJapan:                    "Japanese Japan",
		SubLangKannadaIndia:                     "Kannada India",
		SubLangKashmiriIndia:                    "Kashmiri India",
		SubLangKashmiriSasia:                    "Kashmiri Sasia",
		SubLangKazakKazakhstan:                  "Kazak Kazakhstan",
		SubLangKhmerCambodia:                    "Khmer Cambodia",
		SubLangKicheGuatemala:                   "Kiche Guatemala",
		SubLangKinyarwandaRwanda:                "Kinyarwanda Rwanda",
		SubLangKonkaniIndia:                     "Konkani India",
		SubLangKorean:                           "Korean",
		SubLangKyrgyzKyrgyzstan:                 "Kyrgyz Kyrgyzstan",
		SubLangLaoLao:                           "Lao Lao",
		SubLangLatvianLatvia:                    "Latvian Latvia",
		SubLangLithuanianClassic:                "Lithuanian Classic",
		SubLangLithuanian:                       "Lithuanian",
		SubLangLowerSorbianGermany:              "Lower Sorbian Germany",
		SubLangLuxembourgishLuxembourg:          "Luxembourgish Luxembourg",
		SubLangMacedonianMacedonia:              "Macedonian Macedonia",
		SubLangMalayBruneiDarussalam:            "Malay Brunei Darussalam",
		SubLangMalayMalaysia:                    "Malay Malaysia",
		SubLangMalayalamIndia:                   "Malayalam India",
		SubLangMalteseMalta:                     "Maltese Malta",
		SubLangMaoriNewZealand:                  "Maori New Zealand",
		SubLangMapudungunChile:                  "Mapudungun Chile",
		SubLangMarathiIndia:                     "Marathi India",
		SubLangMohawkMohawk:                     "Mohawk Mohawk",
		SubLangMongolianCyrillicMongolia:        "Mongolian Cyrillic Mongolia",
		SubLangMongolianPrc:                     "Mongolian Prc",
		SubLangNepaliIndia:                      "Nepali India",
		SubLangNepaliNepal:                      "Nepali Nepal",
		SubLangNeutral:                          "Neutral",
		SubLangNorwegianBokmal:                  "Norwegian Bokmal",
		SubLangNorwegianNynorsk:                 "Norwegian Nynorsk",
		SubLangOccitanFrance:                    "Occitan France",
		SubLangOriyaIndia:                       "Oriya India",
		SubLangPashtoAfghanistan:                "Pashto Afghanistan",
		SubLangPersianIran:                      "Persian Iran",
		SubLangPolishPoland:                     "Polish Poland",
		SubLangPortugueseBrazilian:              "Portuguese Brazilian",
		SubLangPortuguese:                       "Portuguese",
		SubLangPunjabiIndia:                     "Punjabi India",
		SubLangQuechuaBolivia:                   "Quechua Bolivia",
		SubLangQuechuaEcuador:                   "Quechua Ecuador",
		SubLangQuechuaPeru:                      "Quechua Peru",
		SubLangRomanianRomania:                  "Romanian Romania",
		SubLangRomanshSwitzerland:               "Romansh Switzerland",
		SubLangRussianRussia:                    "Russian Russia",
		SubLangSamiInariFinland:                 "Sami Inari Finland",
		SubLangSamiLuleNorway:                   "Sami Lule Norway",
		SubLangSamiLuleSweden:                   "Sami Lule Sweden",
		SubLangSamiNorthernFinland:              "Sami Northern Finland",
		SubLangSamiNorthernNorway:               "Sami Northern Norway",
		SubLangSamiNorthernSweden:               "Sami Northern Sweden",
		SubLangSamiSkoltFinland:                 "Sami Skolt Finland",
		SubLangSamiSouthernNorway:               "Sami Southern Norway",
		SubLangSamiSouthernSweden:               "Sami Southern Sweden",
		SubLangSanskritIndia:                    "Sanskrit India",
		SubLangSerbianBosniaHerzegovinaCyrillic: "Serbian Bosnia Herzegovina Cyrillic",
		SubLangSerbianBosniaHerzegovinaLatin:    "Serbian Bosnia Herzegovina Latin",
		SubLangSerbianCroatia:                   "Serbian Croatia",
		SubLangSerbianCyrillic:                  "Serbian Cyrillic",
		SubLangSerbianLatin:                     "Serbian Latin",
		SubLangSindhiAfghanistan:                "Sindhi Afghanistan",
		SubLangSindhiIndia:                      "Sindhi India",
		SubLangSindhiPakistan:                   "Sindhi Pakistan",
		SubLangSinhaleseSriLanka:                "Sinhalese Sri Lanka",
		SubLangSlovakSlovakia:                   "Slovak Slovakia",
		SubLangSlovenianSlovenia:                "Slovenian Slovenia",
		SubLangSothoNorthernSouthAfrica:         "Sotho Northern South Africa",
		SubLangSpanishArgentina:                 "Spanish Argentina",
		SubLangSpanishBolivia:                   "Spanish Bolivia",
		SubLangSpanishChile:                     "Spanish Chile",
		SubLangSpanishColombia:                  "Spanish Colombia",
		SubLangSpanishCostaRica:                 "Spanish Costa Rica",
		SubLangSpanishDominicanRepublic:         "Spanish Dominican Republic",
		SubLangSpanishEcuador:                   "Spanish Ecuador",
		SubLangSpanishElSalvador:                "Spanish El Salvador",
		SubLangSpanishGuatemala:                 "Spanish Guatemala",
		SubLangSpanishHonduras:                  "Spanish Honduras",
		SubLangSpanishMexican:                   "Spanish Mexican",
		SubLangSpanishModern:                    "Spanish Modern",
		SubLangSpanishNicaragua:                 "Spanish Nicaragua",
		SubLangSpanishPanama:                    "Spanish Panama",
		SubLangSpanishParaguay:                  "Spanish Paraguay",
		SubLangSpanishPeru:                      "Spanish Peru",
		SubLangSpanishPuertoRico:                "Spanish Puerto Rico",
		SubLangSpanishUruguay:                   "Spanish Uruguay",
		SubLangSpanishUs:                        "Spanish Us",
		SubLangSpanishVenezuela:                 "Spanish Venezuela",
		SubLangSpanish:                          "Spanish",
		SubLangSwahiliKenya:                     "Swahili Kenya",
		SubLangSwedishFinland:                   "Swedish Finland",
		SubLangSwedish:                          "Swedish",
		SubLangSyriacSyria:                      "Syriac Syria",
		SubLangSysDefault:                       "Sys Default",
		SubLangTajikTajikistan:                  "Tajik Tajikistan",
		SubLangTamazightAlgeriaLatin:            "Tamazight Algeria Latin",
		SubLangTamilIndia:                       "Tamil India",
		SubLangTatarRussia:                      "Tatar Russia",
		SubLangTeluguIndia:                      "Telugu India",
		SubLangThaiThailand:                     "Thai Thailand",
		SubLangTibetanPrc:                       "Tibetan Prc",
		SubLangTigrignaEritrea:                  "Tigrigna Eritrea",
		SubLangTswanaSouthAfrica:                "Tswana South Africa",
		SubLangTurkishTurkey:                    "Turkish Turkey",
		SubLangTurkmenTurkmenistan:              "Turkmen Turkmenistan",
		SubLangUiCustomDefault:                  "Ui Custom Default",
		SubLangUighurPrc:                        "Uighur Prc",
		SubLangUkrainianUkraine:                 "Ukrainian Ukraine",
		SubLangUpperSorbianGermany:              "Upper Sorbian Germany",
		SubLangUrduIndia:                        "Urdu India",
		SubLangUrduPakistan:                     "Urdu Pakistan",
		SubLangUzbekCyrillic:                    "Uzbek Cyrillic",
		SubLangUzbekLatin:                       "Uzbek Latin",
		SubLangVietnameseVietnam:                "Vietnamese Vietnam",
		SubLangWelshUnitedKingdom:               "Welsh United Kingdom",
		SubLangWolofSenegal:                     "Wolof Senegal",
		SubLangXhosaSouthAfrica:                 "Xhosa South Africa",
		SubLangYakutRussia:                      "Yakut Russia",
		SubLangYiPrc:                            "Yi Prc",
		SubLangYorubaNigeria:                    "Yoruba Nigeria",
		SubLangZuluSouthAfrica:                  "Zulu South Africa",
		SubLangPularSenegal:                     "Pular Senegal",
		SubLangPunjabiPakistan:                  "Punjabi Pakistan",
		SubLangTswanaBotswana:                   "Tswana Botswana",
		SubLangTamilSriLanka:                    "Tamil Sri Lanka",
		SubLangTigrinyaEthiopia:                 "Tigrinya Ethiopia",
		SubLangTigrinyaEritrea:                  "Tigrinya Eritrea",
		SubLangValencianValencia:                "Valencian Valencia",
	}

	return rsrcSubLangMap[rsl]
}

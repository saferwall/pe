// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

// Image executable types
const (

	// The DOS MZ executable format is the executable file format used
	// for .EXE files in DOS.
	ImageDOSSignature   = 0x5A4D // MZ
	ImageDOSZMSignature = 0x4D5A // ZM

	// The New Executable (abbreviated NE or NewEXE) is a 16-bit .exe file
	// format, a successor to the DOS MZ executable format. It was used in
	// Windows 1.0–3.x, multitasking MS-DOS 4.0, OS/2 1.x, and the OS/2 subset
	// of Windows NT up to version 5.0 (Windows 2000). A NE is also called a
	// segmented executable.
	ImageOS2Signature = 0x454E

	// Linear Executable is an executable file format in the EXE family.
	// It was used by 32-bit OS/2, by some DOS extenders, and by Microsoft
	// Windows VxD files. It is an extension of MS-DOS EXE, and a successor
	// to NE (New Executable).
	ImageOS2LESignature = 0x454C

	// There are two main varieties of LE executables:
	// LX (32-bit), and LE (mixed 16/32-bit).
	ImageVXDSignature = 0x584C

	// Terse Executables have a 'VZ' signature.
	ImageTESignature = 0x5A56

	// The Portable Executable (PE) format is a file format for executables,
	// object code, DLLs and others used in 32-bit and 64-bit versions of
	// Windows operating systems.
	ImageNTSignature = 0x00004550 // PE00
)

// Optional Header magic
const (
	ImageNtOptionalHeader32Magic = 0x10b
	ImageNtOptionalHeader64Magic = 0x20b
	ImageROMOptionalHeaderMagic  = 0x10
)

// Image file machine types
const (
	ImageFileMachineUnknown   = uint16(0x0)    // The contents of this field are assumed to be applicable to any machine type
	ImageFileMachineAM33      = uint16(0x1d3)  // Matsushita AM33
	ImageFileMachineAMD64     = uint16(0x8664) // x64
	ImageFileMachineARM       = uint16(0x1c0)  // ARM little endian
	ImageFileMachineARM64     = uint16(0xaa64) // ARM64 little endian
	ImageFileMachineARMNT     = uint16(0x1c4)  // ARM Thumb-2 little endian
	ImageFileMachineEBC       = uint16(0xebc)  // EFI byte code
	ImageFileMachineI386      = uint16(0x14c)  // Intel 386 or later processors and compatible processors
	ImageFileMachineIA64      = uint16(0x200)  // Intel Itanium processor family
	ImageFileMachineM32R      = uint16(0x9041) // Mitsubishi M32R little endian
	ImageFileMachineMIPS16    = uint16(0x266)  // MIPS16
	ImageFileMachineMIPSFPU   = uint16(0x366)  // MIPS with FPU
	ImageFileMachineMIPSFPU16 = uint16(0x466)  // MIPS16 with FPU
	ImageFileMachinePowerPC   = uint16(0x1f0)  // Power PC little endian
	ImageFileMachinePowerPCFP = uint16(0x1f1)  // Power PC with floating point support
	ImageFileMachineR4000     = uint16(0x166)  // MIPS little endian
	ImageFileMachineRISCV32   = uint16(0x5032) // RISC-V 32-bit address space
	ImageFileMachineRISCV64   = uint16(0x5064) // RISC-V 64-bit address space
	ImageFileMachineRISCV128  = uint16(0x5128) // RISC-V 128-bit address space
	ImageFileMachineSH3       = uint16(0x1a2)  // Hitachi SH3
	ImageFileMachineSH3DSP    = uint16(0x1a3)  // Hitachi SH3 DSP
	ImageFileMachineSH4       = uint16(0x1a6)  // Hitachi SH4
	ImageFileMachineSH5       = uint16(0x1a8)  // Hitachi SH5
	ImageFileMachineTHUMB     = uint16(0x1c2)  // Thumb
	ImageFileMachineWCEMIPSv2 = uint16(0x169)  // MIPS little-endian WCE v2
)

// The Characteristics field contains flags that indicate attributes of the object or image file.
const (
	// Image file only. This flag indicates that the file contains no base
	// relocations and must be loaded at its preferred base address. In the
	// case of base address conflict, the OS loader reports an error. This flag
	// should not be set for managed PE files.
	ImageFileRelocsStripped = 0x0001

	// Flag indicates that the file is an image file (EXE or DLL). This flag
	// should be set for managed PE files. If it is not set, this generally
	// indicates a linker error (i.e. no unresolved external references).
	ImageFileExecutableImage = 0x0002

	// COFF line numbers have been removed. This flag should be set for managed
	// PE files because they do not use the debug information embedded in the
	// PE file itself. Instead, the debug information is saved in accompanying
	// program database (PDB) files.
	ImageFileLineNumsStripped = 0x0004

	// COFF symbol table entries for local symbols have been removed. This flag
	// should be set for managed PE files, for the reason given in the preceding
	// entry.
	ImageFileLocalSymsStripped = 0x0008

	// Aggressively trim the working set.
	ImageFileAggressiveWSTrim = 0x0010

	// Application can handle addresses beyond the 2GB range. This flag should
	// not be set for pure-IL managed PE files of versions 1.0 and 1.1 but can
	// be set for v2.0+ files.
	ImageFileLargeAddressAware = 0x0020

	// Little endian.
	ImageFileBytesReservedLow = 0x0080

	// Machine is based on 32-bit architecture. This flag is usually set by
	// the current versions of code generators producing managed PE files.
	// Version 2.0 and newer, however, can produce 64-bit specific images,
	// which don’t have this flag set.
	ImageFile32BitMachine = 0x0100

	// Debug information has been removed from the image file.
	ImageFileDebugStripped = 0x0200

	// If the image file is on removable media, copy and run it from the swap
	// file.
	ImageFileRemovableRunFromSwap = 0x0400

	// If the image file is on a network, copy and run it from the swap file.
	ImageFileNetRunFromSwap = 0x0800

	// The image file is a system file (for example, a device driver). This flag
	ImageFileSystem = 0x1000

	// The image file is a DLL rather than an EXE. It cannot be directly run.
	ImageFileDLL = 0x2000

	// The image file should be run on a uniprocessor machine only.
	ImageFileUpSystemOnly = 0x4000

	// Big endian.
	ImageFileBytesReservedHigh = 0x8000
)

// Subsystem values of an OptionalHeader.
const (
	ImageSubsystemUnknown                = 0  // An unknown subsystem.
	ImageSubsystemNative                 = 1  // Device drivers and native Windows processes
	ImageSubsystemWindowsGUI             = 2  // The Windows graphical user interface (GUI) subsystem.
	ImageSubsystemWindowsCUI             = 3  // The Windows character subsystem
	ImageSubsystemOS2CUI                 = 5  // The OS/2 character subsystem.
	ImageSubsystemPosixCUI               = 7  // The Posix character subsystem.
	ImageSubsystemNativeWindows          = 8  // Native Win9x driver
	ImageSubsystemWindowsCEGUI           = 9  // Windows CE
	ImageSubsystemEFIApplication         = 10 // An Extensible Firmware Interface (EFI) application
	ImageSubsystemEFIBootServiceDriver   = 11 // An EFI driver with boot services
	ImageSubsystemEFIRuntimeDriver       = 12 // An EFI driver with run-time services
	ImageSubsystemEFIRom                 = 13 // An EFI ROM image .
	ImageSubsystemXBOX                   = 14 // XBOX.
	ImageSubsystemWindowsBootApplication = 16 // Windows boot application.
)

// DllCharacteristics values of an OptionalHeader
const (
	ImageDllCharacteristicsReserved1            = 0x0001 // Reserved, must be zero.
	ImageDllCharacteristicsReserved2            = 0x0002 // Reserved, must be zero.
	ImageDllCharacteristicsReserved4            = 0x0004 // Reserved, must be zero.
	ImageDllCharacteristicsReserved8            = 0x0008 // Reserved, must be zero.
	ImageDllCharacteristicsHighEntropyVA        = 0x0020 // Image can handle a high entropy 64-bit virtual address space
	ImageDllCharacteristicsDynamicBase          = 0x0040 // DLL can be relocated at load time.
	ImageDllCharacteristicsForceIntegrity       = 0x0080 // Code Integrity checks are enforced.
	ImageDllCharacteristicsNXCompact            = 0x0100 // Image is NX compatible.
	ImageDllCharacteristicsNoIsolation          = 0x0200 // Isolation aware, but do not isolate the image.
	ImageDllCharacteristicsNoSEH                = 0x0400 // Does not use structured exception (SE) handling. No SE handler may be called in this image.
	ImageDllCharacteristicsNoBind               = 0x0800 // Do not bind the image.
	ImageDllCharacteristicsAppContainer         = 0x1000 // Image must execute in an AppContainer
	ImageDllCharacteristicsWdmDriver            = 0x2000 // A WDM driver.
	ImageDllCharacteristicsGuardCF              = 0x4000 // Image supports Control Flow Guard.
	ImageDllCharacteristicsTerminalServiceAware = 0x8000 // Terminal Server aware.

)

// ImageDirectoryEntry represents an entry inside the data directories.
type ImageDirectoryEntry int

// DataDirectory entries of an OptionalHeader
const (
	ImageDirectoryEntryExport       ImageDirectoryEntry = iota // Export Table
	ImageDirectoryEntryImport                                  // Import Table
	ImageDirectoryEntryResource                                // Resource Table
	ImageDirectoryEntryException                               // Exception Table
	ImageDirectoryEntryCertificate                             // Certificate Directory
	ImageDirectoryEntryBaseReloc                               // Base Relocation Table
	ImageDirectoryEntryDebug                                   // Debug
	ImageDirectoryEntryArchitecture                            // Architecture Specific Data
	ImageDirectoryEntryGlobalPtr                               // The RVA of the value to be stored in the global pointer register.
	ImageDirectoryEntryTLS                                     // The thread local storage (TLS) table
	ImageDirectoryEntryLoadConfig                              // The load configuration table
	ImageDirectoryEntryBoundImport                             // The bound import table
	ImageDirectoryEntryIAT                                     // Import Address Table
	ImageDirectoryEntryDelayImport                             // Delay Import Descriptor
	ImageDirectoryEntryCLR                                     // CLR Runtime Header
	ImageDirectoryEntryReserved                                // Must be zero
	ImageNumberOfDirectoryEntries                              // Tables count.
)

// ResourceLang represents a resource language.
type ResourceLang int

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

// ResourceSubLang represents a resource sub language.
type ResourceSubLang int

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

// FileInfo represents the PE file information struct.
type FileInfo struct {
	Is32           bool
	Is64           bool
	HasDOSHdr      bool
	HasRichHdr     bool
	HasCOFF        bool
	HasNTHdr       bool
	HasSections    bool
	HasExport      bool
	HasImport      bool
	HasResource    bool
	HasException   bool
	HasCertificate bool
	HasReloc       bool
	HasDebug       bool
	HasArchitect   bool
	HasGlobalPtr   bool
	HasTLS         bool
	HasLoadCFG     bool
	HasBoundImp    bool
	HasIAT         bool
	HasDelayImp    bool
	HasCLR         bool
	HasOverlay     bool
	IsSigned       bool
}

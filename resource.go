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
type ResourceLang uint32

// ResourceSubLang represents a resource sub language.
type ResourceSubLang uint32

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/70feba9f-294e-491e-b6eb-56532684c37f
// Special resource (sub)language identifiers.
var (
	LangNeutral       ResourceLang = 0x00 // Default custom (MUI) locale language
	LangUserDefault   ResourceLang = 0x01 // User default locale language
	LangSystemDefault ResourceLang = 0x02 // System default locale language
	LangInvariant     ResourceLang = 0x7F // Invariant locale language

	SubLangNeutral           ResourceSubLang = 0x00 // Neutral sub-language
	SubLangInvariant         ResourceSubLang = 0x00 // Invariant sub-language
	SubLangDefault           ResourceSubLang = 0x01 // User default sub-language
	SubLangSysDefault        ResourceSubLang = 0x02 // System default sub-language
	SubLangCustomDefault     ResourceSubLang = 0x03 // Default custom sub-language
	SubLangCustomUnspecified ResourceSubLang = 0x04 // Unspecified custom sub-language
	SubLangMUICustomDefault  ResourceSubLang = 0x05 // Default custom MUI sub-language
)

// All resource (sub)language identifiers.
var (

	// Afrikaans (af)
	LangAfrikaans ResourceLang = 0x0036
	// Afrikaans South Africa (af-ZA)
	SubLangAfrikaansSouthAfrica ResourceSubLang = 0x1

	// Albanian (sq)
	LangAlbanian ResourceLang = 0x001C
	// Albanian Albania (sq-AL)
	SubLangAlbanianAlbania ResourceSubLang = 0x1

	// Alsatian (gsw)
	LangAlsatian ResourceLang = 0x0084
	// Alsatian France (gsw-FR)
	SubLangAlsatianFrance ResourceSubLang = 0x1

	// Amharic (am)
	LangAmharic ResourceLang = 0x005E
	// Amharic Ethiopia (am-ET)
	SubLangAmharicEthiopia ResourceSubLang = 0x1

	// Arabic (ar)
	LangArabic ResourceLang = 0x0001
	// Arabic Algeria (ar-DZ)
	SubLangArabicAlgeria ResourceSubLang = 0x5
	// Arabic Bahrain (ar-BH)
	SubLangArabicBahrain ResourceSubLang = 0xf
	// Arabic Egypt (ar-EG)
	SubLangArabicEgypt ResourceSubLang = 0x3
	// Arabic Iraq (ar-IQ)
	SubLangArabicIraq ResourceSubLang = 0x2
	// Arabic Jordan (ar-JO)
	SubLangArabicJordan ResourceSubLang = 0xb
	// Arabic Kuwait (ar-KW)
	SubLangArabicKuwait ResourceSubLang = 0xd
	// Arabic Lebanon (ar-LB)
	SubLangArabicLebanon ResourceSubLang = 0xc
	// Arabic Libya (ar-LY)
	SubLangArabicLibya ResourceSubLang = 0x4
	// Arabic Morocco (ar-MA)
	SubLangArabicMorocco ResourceSubLang = 0x6
	// Arabic Oman (ar-OM)
	SubLangArabicOman ResourceSubLang = 0x8
	// Arabic Qatar (ar-QA)
	SubLangArabicQatar ResourceSubLang = 0x10
	// Arabic Saudi Arabia (ar-SA)
	SubLangArabicSaudiArabia ResourceSubLang = 0x1
	// Arabic Syria (ar-SY)
	SubLangArabicSyria ResourceSubLang = 0xa
	// Arabic Tunisia (ar-TN)
	SubLangArabicTunisia ResourceSubLang = 0x7
	// Arabic U.a.e. (ar-AE)
	SubLangArabicUae ResourceSubLang = 0xe
	// Arabic Yemen (ar-YE)
	SubLangArabicYemen ResourceSubLang = 0x9

	// Armenian (hy)
	LangArmenian ResourceLang = 0x002B
	// Armenian Armenia (hy-AM)
	SubLangArmenianArmenia ResourceSubLang = 0x1

	// Assamese (as)
	LangAssamese ResourceLang = 0x004D
	// Assamese India (as-IN)
	SubLangAssameseIndia ResourceSubLang = 0x1
	// Azerbaijani (Cyrillic) (az-Cyrl)
	SubLangAzerbaijaniCyrillic ResourceSubLang = 0x1d
	// Azerbaijani (Cyrillic) Azerbaijan (az-Cyrl-AZ)
	SubLangAzerbaijaniCyrillicAzerbaijan ResourceSubLang = 0x2

	// Azerbaijani (Latin) (az)
	LangAzerbaijaniLatin ResourceLang = 0x002C
	// Azerbaijani (Latin) (az-Latn)
	SubLangAzerbaijaniLatin ResourceSubLang = 0x1e
	// Azerbaijani (Latin) Azerbaijan (az-Latn-AZ)
	SubLangAzerbaijaniLatinAzerbaijan ResourceSubLang = 0x1

	// Bangla (bn)
	LangBangla ResourceLang = 0x0045
	// Bangla Bangladesh (bn-BD)
	SubLangBanglaBangladesh ResourceSubLang = 0x2
	// Bangla India (bn-IN)
	SubLangBanglaIndia ResourceSubLang = 0x1

	// Bashkir (ba)
	LangBashkir ResourceLang = 0x006D
	// Bashkir Russia (ba-RU)
	SubLangBashkirRussia ResourceSubLang = 0x1

	// Basque (eu)
	LangBasque ResourceLang = 0x002D
	// Basque Spain (eu-ES)
	SubLangBasqueSpain ResourceSubLang = 0x1

	// Belarusian (be)
	LangBelarusian ResourceLang = 0x0023
	// Belarusian Belarus (be-BY)
	SubLangBelarusianBelarus ResourceSubLang = 0x1
	// Bosnian (Cyrillic) (bs-Cyrl)
	SubLangBosnianCyrillic ResourceSubLang = 0x19
	// Bosnian (Cyrillic) Bosnia And Herzegovina (bs-Cyrl-BA)
	SubLangBosnianCyrillicBosniaAndHerzegovina ResourceSubLang = 0x8
	// Bosnian (Latin) (bs-Latn)
	SubLangBosnianLatin ResourceSubLang = 0x1a

	// Bosnian (Latin) (bs)
	LangBosnianLatin ResourceLang = 0x781A
	// Bosnian (Latin) Bosnia And Herzegovina (bs-Latn-BA)
	SubLangBosnianLatinBosniaAndHerzegovina ResourceSubLang = 0x5

	// Breton (br)
	LangBreton ResourceLang = 0x007E
	// Breton France (br-FR)
	SubLangBretonFrance ResourceSubLang = 0x1

	// Bulgarian (bg)
	LangBulgarian ResourceLang = 0x0002
	// Bulgarian Bulgaria (bg-BG)
	SubLangBulgarianBulgaria ResourceSubLang = 0x1

	// Burmese (my)
	LangBurmese ResourceLang = 0x0055
	// Burmese Myanmar (my-MM)
	SubLangBurmeseMyanmar ResourceSubLang = 0x1

	// Catalan (ca)
	LangCatalan ResourceLang = 0x0003
	// Catalan Spain (ca-ES)
	SubLangCatalanSpain ResourceSubLang = 0x1

	// Central Kurdish (ku)
	LangCentralKurdish ResourceLang = 0x0092
	// Central Kurdish (ku-Arab)
	SubLangCentralKurdish ResourceSubLang = 0x1f
	// Central Kurdish Iraq (ku-Arab-IQ)
	SubLangCentralKurdishIraq ResourceSubLang = 0x1

	// Cherokee (chr)
	LangCherokee ResourceLang = 0x005C
	// Cherokee (chr-Cher)
	SubLangCherokee ResourceSubLang = 0x1f
	// Cherokee United States (chr-Cher-US)
	SubLangCherokeeUnitedStates ResourceSubLang = 0x1
	// Chinese (Simplified) (zh-Hans)
	SubLangChineseSimplified ResourceSubLang = 0x0

	// Chinese (Simplified) (zh)
	LangChineseSimplified ResourceLang = 0x7804
	// Chinese (Simplified) People's Republic Of China (zh-CN)
	SubLangChineseSimplifiedPeoplesRepublicOfChina ResourceSubLang = 0x2
	// Chinese (Simplified) Singapore (zh-SG)
	SubLangChineseSimplifiedSingapore ResourceSubLang = 0x4
	// Chinese (Traditional) (zh-Hant)
	SubLangChineseTraditional ResourceSubLang = 0x1f
	// Chinese (Traditional) Hong Kong S.a.r. (zh-HK)
	SubLangChineseTraditionalHongKongSar ResourceSubLang = 0x3
	// Chinese (Traditional) Macao S.a.r. (zh-MO)
	SubLangChineseTraditionalMacaoSar ResourceSubLang = 0x5
	// Chinese (Traditional) Taiwan (zh-TW)
	SubLangChineseTraditionalTaiwan ResourceSubLang = 0x1

	// Corsican (co)
	LangCorsican ResourceLang = 0x0083
	// Corsican France (co-FR)
	SubLangCorsicanFrance ResourceSubLang = 0x1

	// Croatian (hr)
	LangCroatian ResourceLang = 0x001A
	// Croatian Croatia (hr-HR)
	SubLangCroatianCroatia ResourceSubLang = 0x1
	// Croatian (Latin) Bosnia And Herzegovina (hr-BA)
	SubLangCroatianLatinBosniaAndHerzegovina ResourceSubLang = 0x4

	// Czech (cs)
	LangCzech ResourceLang = 0x0005
	// Czech Czech Republic (cs-CZ)
	SubLangCzechCzechRepublic ResourceSubLang = 0x1

	// Danish (da)
	LangDanish ResourceLang = 0x0006
	// Danish Denmark (da-DK)
	SubLangDanishDenmark ResourceSubLang = 0x1

	// Dari (prs)
	LangDari ResourceLang = 0x008C
	// Dari Afghanistan (prs-AF)
	SubLangDariAfghanistan ResourceSubLang = 0x1

	// Divehi (dv)
	LangDivehi ResourceLang = 0x0065
	// Divehi Maldives (dv-MV)
	SubLangDivehiMaldives ResourceSubLang = 0x1

	// Dutch (nl)
	LangDutch ResourceLang = 0x0013
	// Dutch Belgium (nl-BE)
	SubLangDutchBelgium ResourceSubLang = 0x2
	// Dutch Netherlands (nl-NL)
	SubLangDutchNetherlands ResourceSubLang = 0x1
	// Dzongkha Bhutan (dz-BT)
	SubLangDzongkhaBhutan ResourceSubLang = 0x3

	// English (en)
	LangEnglish ResourceLang = 0x0009
	// English Australia (en-AU)
	SubLangEnglishAustralia ResourceSubLang = 0x3
	// English Belize (en-BZ)
	SubLangEnglishBelize ResourceSubLang = 0xa
	// English Canada (en-CA)
	SubLangEnglishCanada ResourceSubLang = 0x4
	// English Caribbean (en-029)
	SubLangEnglishCaribbean ResourceSubLang = 0x9
	// English Hong Kong (en-HK)
	SubLangEnglishHongKong ResourceSubLang = 0xf
	// English India (en-IN)
	SubLangEnglishIndia ResourceSubLang = 0x10
	// English Ireland (en-IE)
	SubLangEnglishIreland ResourceSubLang = 0x6
	// English Jamaica (en-JM)
	SubLangEnglishJamaica ResourceSubLang = 0x8
	// English Malaysia (en-MY)
	SubLangEnglishMalaysia ResourceSubLang = 0x11
	// English New Zealand (en-NZ)
	SubLangEnglishNewZealand ResourceSubLang = 0x5
	// English Republic Of The Philippines (en-PH)
	SubLangEnglishRepublicOfThePhilippines ResourceSubLang = 0xd
	// English Singapore (en-SG)
	SubLangEnglishSingapore ResourceSubLang = 0x12
	// English South Africa (en-ZA)
	SubLangEnglishSouthAfrica ResourceSubLang = 0x7
	// English Trinidad And Tobago (en-TT)
	SubLangEnglishTrinidadAndTobago ResourceSubLang = 0xb
	// English United Arab Emirates (en-AE)
	SubLangEnglishUnitedArabEmirates ResourceSubLang = 0x13
	// English United Kingdom (en-GB)
	SubLangEnglishUnitedKingdom ResourceSubLang = 0x2
	// English United States (en-US)
	SubLangEnglishUnitedStates ResourceSubLang = 0x1
	// English Zimbabwe (en-ZW)
	SubLangEnglishZimbabwe ResourceSubLang = 0xc

	// Estonian (et)
	LangEstonian ResourceLang = 0x0025
	// Estonian Estonia (et-EE)
	SubLangEstonianEstonia ResourceSubLang = 0x1

	// Faroese (fo)
	LangFaroese ResourceLang = 0x0038
	// Faroese Faroe Islands (fo-FO)
	SubLangFaroeseFaroeIslands ResourceSubLang = 0x1

	// Filipino (fil)
	LangFilipino ResourceLang = 0x0064
	// Filipino Philippines (fil-PH)
	SubLangFilipinoPhilippines ResourceSubLang = 0x1

	// Finnish (fi)
	LangFinnish ResourceLang = 0x000B
	// Finnish Finland (fi-FI)
	SubLangFinnishFinland ResourceSubLang = 0x1

	// French (fr)
	LangFrench ResourceLang = 0x000C
	// French Belgium (fr-BE)
	SubLangFrenchBelgium ResourceSubLang = 0x2
	// French Cameroon (fr-CM)
	SubLangFrenchCameroon ResourceSubLang = 0xb
	// French Canada (fr-CA)
	SubLangFrenchCanada ResourceSubLang = 0x3
	// French Caribbean (fr-029)
	SubLangFrenchCaribbean ResourceSubLang = 0x7
	// French Congo, Drc (fr-CD)
	SubLangFrenchCongoDrc ResourceSubLang = 0x9
	// French Côte D'ivoire (fr-CI)
	SubLangFrenchCôteDivoire ResourceSubLang = 0xc
	// French France (fr-FR)
	SubLangFrenchFrance ResourceSubLang = 0x1
	// French Haiti (fr-HT)
	SubLangFrenchHaiti ResourceSubLang = 0xf
	// French Luxembourg (fr-LU)
	SubLangFrenchLuxembourg ResourceSubLang = 0x5
	// French Mali (fr-ML)
	SubLangFrenchMali ResourceSubLang = 0xd
	// French Morocco (fr-MA)
	SubLangFrenchMorocco ResourceSubLang = 0xe
	// French Principality Of Monaco (fr-MC)
	SubLangFrenchPrincipalityOfMonaco ResourceSubLang = 0x6
	// French Reunion (fr-RE)
	SubLangFrenchReunion ResourceSubLang = 0x8
	// French Senegal (fr-SN)
	SubLangFrenchSenegal ResourceSubLang = 0xa
	// French Switzerland (fr-CH)
	SubLangFrenchSwitzerland ResourceSubLang = 0x4

	// Frisian (fy)
	LangFrisian ResourceLang = 0x0062
	// Frisian Netherlands (fy-NL)
	SubLangFrisianNetherlands ResourceSubLang = 0x1

	// Fulah (ff)
	LangFulah ResourceLang = 0x0067
	// Fulah (Latin) (ff-Latn)
	SubLangFulahLatin ResourceSubLang = 0x1f
	// Fulah Nigeria (ff-NG)
	SubLangFulahNigeria ResourceSubLang = 0x1
	// Fulah (Latin) Nigeria (ff-Latn-NG)
	SubLangFulahLatinNigeria ResourceSubLang = 0x1
	// Fulah Senegal (ff-Latn-SN)
	SubLangFulahSenegal ResourceSubLang = 0x2

	// Galician (gl)
	LangGalician ResourceLang = 0x0056
	// Galician Spain (gl-ES)
	SubLangGalicianSpain ResourceSubLang = 0x1

	// Georgian (ka)
	LangGeorgian ResourceLang = 0x0037
	// Georgian Georgia (ka-GE)
	SubLangGeorgianGeorgia ResourceSubLang = 0x1

	// German (de)
	LangGerman ResourceLang = 0x0007
	// German Austria (de-AT)
	SubLangGermanAustria ResourceSubLang = 0x3
	// German Germany (de-DE)
	SubLangGermanGermany ResourceSubLang = 0x1
	// German Liechtenstein (de-LI)
	SubLangGermanLiechtenstein ResourceSubLang = 0x5
	// German Luxembourg (de-LU)
	SubLangGermanLuxembourg ResourceSubLang = 0x4
	// German Switzerland (de-CH)
	SubLangGermanSwitzerland ResourceSubLang = 0x2

	// Greek (el)
	LangGreek ResourceLang = 0x0008
	// Greek Greece (el-GR)
	SubLangGreekGreece ResourceSubLang = 0x1

	// Greenlandic (kl)
	LangGreenlandic ResourceLang = 0x006F
	// Greenlandic Greenland (kl-GL)
	SubLangGreenlandicGreenland ResourceSubLang = 0x1

	// Guarani (gn)
	LangGuarani ResourceLang = 0x0074
	// Guarani Paraguay (gn-PY)
	SubLangGuaraniParaguay ResourceSubLang = 0x1

	// Gujarati (gu)
	LangGujarati ResourceLang = 0x0047
	// Gujarati India (gu-IN)
	SubLangGujaratiIndia ResourceSubLang = 0x1

	// Hausa (Latin) (ha)
	LangHausaLatin ResourceLang = 0x0068
	// Hausa (Latin) (ha-Latn)
	SubLangHausaLatin ResourceSubLang = 0x1f
	// Hausa (Latin) Nigeria (ha-Latn-NG)
	SubLangHausaLatinNigeria ResourceSubLang = 0x1

	// Hawaiian (haw)
	LangHawaiian ResourceLang = 0x0075
	// Hawaiian United States (haw-US)
	SubLangHawaiianUnitedStates ResourceSubLang = 0x1

	// Hebrew (he)
	LangHebrew ResourceLang = 0x000D
	// Hebrew Israel (he-IL)
	SubLangHebrewIsrael ResourceSubLang = 0x1

	// Hindi (hi)
	LangHindi ResourceLang = 0x0039
	// Hindi India (hi-IN)
	SubLangHindiIndia ResourceSubLang = 0x1

	// Hungarian (hu)
	LangHungarian ResourceLang = 0x000E
	// Hungarian Hungary (hu-HU)
	SubLangHungarianHungary ResourceSubLang = 0x1

	// Icelandic (is)
	LangIcelandic ResourceLang = 0x000F
	// Icelandic Iceland (is-IS)
	SubLangIcelandicIceland ResourceSubLang = 0x1

	// Igbo (ig)
	LangIgbo ResourceLang = 0x0070
	// Igbo Nigeria (ig-NG)
	SubLangIgboNigeria ResourceSubLang = 0x1

	// Indonesian (id)
	LangIndonesian ResourceLang = 0x0021
	// Indonesian Indonesia (id-ID)
	SubLangIndonesianIndonesia ResourceSubLang = 0x1

	// Inuktitut (Latin) (iu)
	LangInuktitutLatin ResourceLang = 0x005D
	// Inuktitut (Latin) (iu-Latn)
	SubLangInuktitutLatin ResourceSubLang = 0x1f
	// Inuktitut (Latin) Canada (iu-Latn-CA)
	SubLangInuktitutLatinCanada ResourceSubLang = 0x2
	// Inuktitut (Syllabics) (iu-Cans)
	SubLangInuktitutSyllabics ResourceSubLang = 0x1e
	// Inuktitut (Syllabics) Canada (iu-Cans-CA)
	SubLangInuktitutSyllabicsCanada ResourceSubLang = 0x1

	// Irish (ga)
	LangIrish ResourceLang = 0x003C
	// Irish Ireland (ga-IE)
	SubLangIrishIreland ResourceSubLang = 0x2

	// Italian (it)
	LangItalian ResourceLang = 0x0010
	// Italian Italy (it-IT)
	SubLangItalianItaly ResourceSubLang = 0x1
	// Italian Switzerland (it-CH)
	SubLangItalianSwitzerland ResourceSubLang = 0x2

	// Japanese (ja)
	LangJapanese ResourceLang = 0x0011
	// Japanese Japan (ja-JP)
	SubLangJapaneseJapan ResourceSubLang = 0x1

	// Kannada (kn)
	LangKannada ResourceLang = 0x004B
	// Kannada India (kn-IN)
	SubLangKannadaIndia ResourceSubLang = 0x1
	// Kanuri (Latin) Nigeria (kr-Latn-NG)
	SubLangKanuriLatinNigeria ResourceSubLang = 0x1

	// Kashmiri (ks)
	LangKashmiri ResourceLang = 0x0060
	// Kashmiri Perso-Arabic (ks-Arab)
	SubLangKashmiriPersoArabic ResourceSubLang = 0x1
	// Kashmiri (Devanagari) India (ks-Deva-IN)
	SubLangKashmiriDevanagariIndia ResourceSubLang = 0x2

	// Kazakh (kk)
	LangKazakh ResourceLang = 0x003F
	// Kazakh Kazakhstan (kk-KZ)
	SubLangKazakhKazakhstan ResourceSubLang = 0x1

	// Khmer (km)
	LangKhmer ResourceLang = 0x0053
	// Khmer Cambodia (km-KH)
	SubLangKhmerCambodia ResourceSubLang = 0x1

	// K'iche (quc)
	LangKiche ResourceLang = 0x0086
	// K'iche Guatemala (quc-Latn-GT)
	SubLangKicheGuatemala ResourceSubLang = 0x1

	// Kinyarwanda (rw)
	LangKinyarwanda ResourceLang = 0x0087
	// Kinyarwanda Rwanda (rw-RW)
	SubLangKinyarwandaRwanda ResourceSubLang = 0x1

	// Kiswahili (sw)
	LangKiswahili ResourceLang = 0x0041
	// Kiswahili Kenya (sw-KE)
	SubLangKiswahiliKenya ResourceSubLang = 0x1

	// Konkani (kok)
	LangKonkani ResourceLang = 0x0057
	// Konkani India (kok-IN)
	SubLangKonkaniIndia ResourceSubLang = 0x1

	// Korean (ko)
	LangKorean ResourceLang = 0x0012
	// Korean Korea (ko-KR)
	SubLangKoreanKorea ResourceSubLang = 0x1

	// Kyrgyz (ky)
	LangKyrgyz ResourceLang = 0x0040
	// Kyrgyz Kyrgyzstan (ky-KG)
	SubLangKyrgyzKyrgyzstan ResourceSubLang = 0x1

	// Lao (lo)
	LangLao ResourceLang = 0x0054
	// Lao Lao P.d.r. (lo-LA)
	SubLangLaoLaoPdr ResourceSubLang = 0x1
	// Latin Vatican City (la-VA)
	SubLangLatinVaticanCity ResourceSubLang = 0x1

	// Latvian (lv)
	LangLatvian ResourceLang = 0x0026
	// Latvian Latvia (lv-LV)
	SubLangLatvianLatvia ResourceSubLang = 0x1

	// Lithuanian (lt)
	LangLithuanian ResourceLang = 0x0027
	// Lithuanian Lithuania (lt-LT)
	SubLangLithuanianLithuania ResourceSubLang = 0x1

	// Lower Sorbian (dsb)
	LangLowerSorbian ResourceLang = 0x7C2E
	// Lower Sorbian Germany (dsb-DE)
	SubLangLowerSorbianGermany ResourceSubLang = 0x2

	// Luxembourgish (lb)
	LangLuxembourgish ResourceLang = 0x006E
	// Luxembourgish Luxembourg (lb-LU)
	SubLangLuxembourgishLuxembourg ResourceSubLang = 0x1

	// Macedonian (mk)
	LangMacedonian ResourceLang = 0x002F
	// Macedonian North Macedonia (mk-MK)
	SubLangMacedonianNorthMacedonia ResourceSubLang = 0x1

	// Malay (ms)
	LangMalay ResourceLang = 0x003E
	// Malay Brunei Darussalam (ms-BN)
	SubLangMalayBruneiDarussalam ResourceSubLang = 0x2
	// Malay Malaysia (ms-MY)
	SubLangMalayMalaysia ResourceSubLang = 0x1

	// Malayalam (ml)
	LangMalayalam ResourceLang = 0x004C
	// Malayalam India (ml-IN)
	SubLangMalayalamIndia ResourceSubLang = 0x1

	// Maltese (mt)
	LangMaltese ResourceLang = 0x003A
	// Maltese Malta (mt-MT)
	SubLangMalteseMalta ResourceSubLang = 0x1

	// Maori (mi)
	LangMaori ResourceLang = 0x0081
	// Maori New Zealand (mi-NZ)
	SubLangMaoriNewZealand ResourceSubLang = 0x1

	// Mapudungun (arn)
	LangMapudungun ResourceLang = 0x007A
	// Mapudungun Chile (arn-CL)
	SubLangMapudungunChile ResourceSubLang = 0x1

	// Marathi (mr)
	LangMarathi ResourceLang = 0x004E
	// Marathi India (mr-IN)
	SubLangMarathiIndia ResourceSubLang = 0x1

	// Mohawk (moh)
	LangMohawk ResourceLang = 0x007C
	// Mohawk Canada (moh-CA)
	SubLangMohawkCanada ResourceSubLang = 0x1

	// Mongolian (Cyrillic) (mn)
	LangMongolianCyrillic ResourceLang = 0x0050
	// Mongolian (Cyrillic) (mn-Cyrl)
	SubLangMongolianCyrillic ResourceSubLang = 0x1e
	// Mongolian (Cyrillic) Mongolia (mn-MN)
	SubLangMongolianCyrillicMongolia ResourceSubLang = 0x1
	// Mongolian (Traditional Mongolian) (mn-Mong)
	SubLangMongolianTraditionalMongolian ResourceSubLang = 0x1f
	// Mongolian (Traditional Mongolian) People's Republic Of China (mn-MongCN)
	SubLangMongolianTraditionalMongolianPeoplesRepublicOfChina ResourceSubLang = 0x2
	// Mongolian (Traditional Mongolian) Mongolia (mn-MongMN)
	SubLangMongolianTraditionalMongolianMongolia ResourceSubLang = 0x3

	// Nepali (ne)
	LangNepali ResourceLang = 0x0061
	// Nepali India (ne-IN)
	SubLangNepaliIndia ResourceSubLang = 0x2
	// Nepali Nepal (ne-NP)
	SubLangNepaliNepal ResourceSubLang = 0x1

	// Norwegian (Bokmal) (no)
	LangNorwegianBokmal1 ResourceLang = 0x0014

	// Norwegian (Bokmal) (nb)
	LangNorwegianBokmal ResourceLang = 0x7C14
	// Norwegian (Bokmal) Norway (nb-NO)
	SubLangNorwegianBokmalNorway ResourceSubLang = 0x1

	// Norwegian (Nynorsk) (nn)
	LangNorwegianNynorsk ResourceLang = 0x7814
	// Norwegian (Nynorsk) Norway (nn-NO)
	SubLangNorwegianNynorskNorway ResourceSubLang = 0x2

	// Occitan (oc)
	LangOccitan ResourceLang = 0x0082
	// Occitan France (oc-FR)
	SubLangOccitanFrance ResourceSubLang = 0x1

	// Odia (or)
	LangOdia ResourceLang = 0x0048
	// Odia India (or-IN)
	SubLangOdiaIndia ResourceSubLang = 0x1

	// Oromo (om)
	LangOromo ResourceLang = 0x0072
	// Oromo Ethiopia (om-ET)
	SubLangOromoEthiopia ResourceSubLang = 0x1

	// Pashto (ps)
	LangPashto ResourceLang = 0x0063
	// Pashto Afghanistan (ps-AF)
	SubLangPashtoAfghanistan ResourceSubLang = 0x1

	// Persian (fa)
	LangPersian ResourceLang = 0x0029
	// Persian Iran (fa-IR)
	SubLangPersianIran ResourceSubLang = 0x1

	// Polish (pl)
	LangPolish ResourceLang = 0x0015
	// Polish Poland (pl-PL)
	SubLangPolishPoland ResourceSubLang = 0x1

	// Portuguese (pt)
	LangPortuguese ResourceLang = 0x0016
	// Portuguese Brazil (pt-BR)
	SubLangPortugueseBrazil ResourceSubLang = 0x1
	// Portuguese Portugal (pt-PT)
	SubLangPortuguesePortugal ResourceSubLang = 0x2
	// Pseudo Language Pseudo Locale For East Asian/complex Script Localization Testing (qps-ploca)
	SubLangPseudoLanguagePseudoLocaleForEastAsianComplexScriptLocalizationTesting ResourceSubLang = 0x1
	// Pseudo Language Pseudo Locale Used For Localization Testing (qps-ploc)
	SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTesting ResourceSubLang = 0x1
	// Pseudo Language Pseudo Locale Used For Localization Testing Of Mirrored Locales (qps-plocm)
	SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTestingOfMirroredLocales ResourceSubLang = 0x2

	// Punjabi (pa)
	LangPunjabi ResourceLang = 0x0046
	// Punjabi (pa-Arab)
	SubLangPunjabi ResourceSubLang = 0x1f
	// Punjabi India (pa-IN)
	SubLangPunjabiIndia ResourceSubLang = 0x1
	// Punjabi Islamic Republic Of Pakistan (pa-Arab-PK)
	SubLangPunjabiIslamicRepublicOfPakistan ResourceSubLang = 0x2

	// Quechua (quz)
	LangQuechua ResourceLang = 0x006B
	// Quechua Bolivia (quz-BO)
	SubLangQuechuaBolivia ResourceSubLang = 0x1
	// Quechua Ecuador (quz-EC)
	SubLangQuechuaEcuador ResourceSubLang = 0x2
	// Quechua Peru (quz-PE)
	SubLangQuechuaPeru ResourceSubLang = 0x3

	// Romanian (ro)
	LangRomanian ResourceLang = 0x0018
	// Romanian Moldova (ro-MD)
	SubLangRomanianMoldova ResourceSubLang = 0x2
	// Romanian Romania (ro-RO)
	SubLangRomanianRomania ResourceSubLang = 0x1

	// Romansh (rm)
	LangRomansh ResourceLang = 0x0017
	// Romansh Switzerland (rm-CH)
	SubLangRomanshSwitzerland ResourceSubLang = 0x1

	// Russian (ru)
	LangRussian ResourceLang = 0x0019
	// Russian Moldova (ru-MD)
	SubLangRussianMoldova ResourceSubLang = 0x2
	// Russian Russia (ru-RU)
	SubLangRussianRussia ResourceSubLang = 0x1

	// Sakha (sah)
	LangSakha ResourceLang = 0x0085
	// Sakha Russia (sah-RU)
	SubLangSakhaRussia ResourceSubLang = 0x1

	// Sami (Inari) (smn)
	LangSamiInari ResourceLang = 0x703B
	// Sami (Inari) Finland (smn-FI)
	SubLangSamiInariFinland ResourceSubLang = 0x9

	// Sami (Lule) (smj)
	LangSamiLule ResourceLang = 0x7C3B
	// Sami (Lule) Norway (smj-NO)
	SubLangSamiLuleNorway ResourceSubLang = 0x4
	// Sami (Lule) Sweden (smj-SE)
	SubLangSamiLuleSweden ResourceSubLang = 0x5

	// Sami (Northern) (se)
	LangSamiNorthern ResourceLang = 0x003B
	// Sami (Northern) Finland (se-FI)
	SubLangSamiNorthernFinland ResourceSubLang = 0x3
	// Sami (Northern) Norway (se-NO)
	SubLangSamiNorthernNorway ResourceSubLang = 0x1
	// Sami (Northern) Sweden (se-SE)
	SubLangSamiNorthernSweden ResourceSubLang = 0x2

	// Sami (Skolt) (sms)
	LangSamiSkolt ResourceLang = 0x743B
	// Sami (Skolt) Finland (sms-FI)
	SubLangSamiSkoltFinland ResourceSubLang = 0x8

	// Sami (Southern) (sma)
	LangSamiSouthern ResourceLang = 0x783B
	// Sami (Southern) Norway (sma-NO)
	SubLangSamiSouthernNorway ResourceSubLang = 0x6
	// Sami (Southern) Sweden (sma-SE)
	SubLangSamiSouthernSweden ResourceSubLang = 0x7

	// Sanskrit (sa)
	LangSanskrit ResourceLang = 0x004F
	// Sanskrit India (sa-IN)
	SubLangSanskritIndia ResourceSubLang = 0x1

	// Scottish Gaelic (gd)
	LangScottishGaelic ResourceLang = 0x0091
	// Scottish Gaelic United Kingdom (gd-GB)
	SubLangScottishGaelicUnitedKingdom ResourceSubLang = 0x1
	// Serbian (Cyrillic) (sr-Cyrl)
	SubLangSerbianCyrillic ResourceSubLang = 0x1b
	// Serbian (Cyrillic) Bosnia And Herzegovina (sr-Cyrl-BA)
	SubLangSerbianCyrillicBosniaAndHerzegovina ResourceSubLang = 0x7
	// Serbian (Cyrillic) Montenegro (sr-Cyrl-ME)
	SubLangSerbianCyrillicMontenegro ResourceSubLang = 0xc
	// Serbian (Cyrillic) Serbia (sr-Cyrl-RS)
	SubLangSerbianCyrillicSerbia ResourceSubLang = 0xa
	// Serbian (Cyrillic) Serbia And Montenegro (former) (sr-Cyrl-CS)
	SubLangSerbianCyrillicSerbiaAndMontenegroFormer ResourceSubLang = 0x3
	// Serbian (Latin) (sr-Latn)
	SubLangSerbianLatin ResourceSubLang = 0x1c

	// Serbian (Latin) (sr)
	LangSerbianLatin ResourceLang = 0x7C1A
	// Serbian (Latin) Bosnia And Herzegovina (sr-Latn-BA)
	SubLangSerbianLatinBosniaAndHerzegovina ResourceSubLang = 0x6
	// Serbian (Latin) Montenegro (sr-Latn-ME)
	SubLangSerbianLatinMontenegro ResourceSubLang = 0xb
	// Serbian (Latin) Serbia (sr-Latn-RS)
	SubLangSerbianLatinSerbia ResourceSubLang = 0x9
	// Serbian (Latin) Serbia And Montenegro (former) (sr-Latn-CS)
	SubLangSerbianLatinSerbiaAndMontenegroFormer ResourceSubLang = 0x2

	// Sesotho Sa Leboa (nso)
	LangSesothoSaLeboa ResourceLang = 0x006C
	// Sesotho Sa Leboa South Africa (nso-ZA)
	SubLangSesothoSaLeboaSouthAfrica ResourceSubLang = 0x1

	// Setswana (tn)
	LangSetswana ResourceLang = 0x0032
	// Setswana Botswana (tn-BW)
	SubLangSetswanaBotswana ResourceSubLang = 0x2
	// Setswana South Africa (tn-ZA)
	SubLangSetswanaSouthAfrica ResourceSubLang = 0x1

	// Sindhi (sd)
	LangSindhi ResourceLang = 0x0059
	// Sindhi (sd-Arab)
	SubLangSindhi ResourceSubLang = 0x1f
	// Sindhi Islamic Republic Of Pakistan (sd-Arab-PK)
	SubLangSindhiIslamicRepublicOfPakistan ResourceSubLang = 0x2

	// Sinhala (si)
	LangSinhala ResourceLang = 0x005B
	// Sinhala Sri Lanka (si-LK)
	SubLangSinhalaSriLanka ResourceSubLang = 0x1

	// Slovak (sk)
	LangSlovak ResourceLang = 0x001B
	// Slovak Slovakia (sk-SK)
	SubLangSlovakSlovakia ResourceSubLang = 0x1

	// Slovenian (sl)
	LangSlovenian ResourceLang = 0x0024
	// Slovenian Slovenia (sl-SI)
	SubLangSlovenianSlovenia ResourceSubLang = 0x1

	// Somali (so)
	LangSomali ResourceLang = 0x0077
	// Somali Somalia (so-SO)
	SubLangSomaliSomalia ResourceSubLang = 0x1

	// Sotho (st)
	LangSotho ResourceLang = 0x0030
	// Sotho South Africa (st-ZA)
	SubLangSothoSouthAfrica ResourceSubLang = 0x1

	// Spanish (es)
	LangSpanish ResourceLang = 0x000A
	// Spanish Argentina (es-AR)
	SubLangSpanishArgentina ResourceSubLang = 0xb
	// Spanish Bolivarian Republic Of Venezuela (es-VE)
	SubLangSpanishBolivarianRepublicOfVenezuela ResourceSubLang = 0x8
	// Spanish Bolivia (es-BO)
	SubLangSpanishBolivia ResourceSubLang = 0x10
	// Spanish Chile (es-CL)
	SubLangSpanishChile ResourceSubLang = 0xd
	// Spanish Colombia (es-CO)
	SubLangSpanishColombia ResourceSubLang = 0x9
	// Spanish Costa Rica (es-CR)
	SubLangSpanishCostaRica ResourceSubLang = 0x5
	// Spanish Cuba (es-CU)
	SubLangSpanishCuba ResourceSubLang = 0x17
	// Spanish Dominican Republic (es-DO)
	SubLangSpanishDominicanRepublic ResourceSubLang = 0x7
	// Spanish Ecuador (es-EC)
	SubLangSpanishEcuador ResourceSubLang = 0xc
	// Spanish El Salvador (es-SV)
	SubLangSpanishElSalvador ResourceSubLang = 0x11
	// Spanish Guatemala (es-GT)
	SubLangSpanishGuatemala ResourceSubLang = 0x4
	// Spanish Honduras (es-HN)
	SubLangSpanishHonduras ResourceSubLang = 0x12
	// Spanish Latin America (es-419)
	SubLangSpanishLatinAmerica ResourceSubLang = 0x16
	// Spanish Mexico (es-MX)
	SubLangSpanishMexico ResourceSubLang = 0x2
	// Spanish Nicaragua (es-NI)
	SubLangSpanishNicaragua ResourceSubLang = 0x13
	// Spanish Panama (es-PA)
	SubLangSpanishPanama ResourceSubLang = 0x6
	// Spanish Paraguay (es-PY)
	SubLangSpanishParaguay ResourceSubLang = 0xf
	// Spanish Peru (es-PE)
	SubLangSpanishPeru ResourceSubLang = 0xa
	// Spanish Puerto Rico (es-PR)
	SubLangSpanishPuertoRico ResourceSubLang = 0x14
	// Spanish Spain (es-ES_tradnl)
	SubLangSpanishSpainTraditional ResourceSubLang = 0x1
	// Spanish Spain (es-ES)
	SubLangSpanishSpain ResourceSubLang = 0x3
	// Spanish United States (es-US)
	SubLangSpanishUnitedStates ResourceSubLang = 0x15
	// Spanish Uruguay (es-UY)
	SubLangSpanishUruguay ResourceSubLang = 0xe

	// Swedish (sv)
	LangSwedish ResourceLang = 0x001D
	// Swedish Finland (sv-FI)
	SubLangSwedishFinland ResourceSubLang = 0x2
	// Swedish Sweden (sv-SE)
	SubLangSwedishSweden ResourceSubLang = 0x1

	// Syriac (syr)
	LangSyriac ResourceLang = 0x005A
	// Syriac Syria (syr-SY)
	SubLangSyriacSyria ResourceSubLang = 0x1

	// Tajik (Cyrillic) (tg)
	LangTajikCyrillic ResourceLang = 0x0028
	// Tajik (Cyrillic) (tg-Cyrl)
	SubLangTajikCyrillic ResourceSubLang = 0x1f
	// Tajik (Cyrillic) Tajikistan (tg-Cyrl-TJ)
	SubLangTajikCyrillicTajikistan ResourceSubLang = 0x1

	// Tamazight (Latin) (tzm)
	LangTamazightLatin ResourceLang = 0x005F
	// Tamazight (Latin) (tzm-Latn)
	SubLangTamazightLatin ResourceSubLang = 0x1f
	// Tamazight (Latin) Algeria (tzm-Latn-DZ)
	SubLangTamazightLatinAlgeria ResourceSubLang = 0x2

	// Tamil (ta)
	LangTamil ResourceLang = 0x0049
	// Tamil India (ta-IN)
	SubLangTamilIndia ResourceSubLang = 0x1
	// Tamil Sri Lanka (ta-LK)
	SubLangTamilSriLanka ResourceSubLang = 0x2

	// Tatar (tt)
	LangTatar ResourceLang = 0x0044
	// Tatar Russia (tt-RU)
	SubLangTatarRussia ResourceSubLang = 0x1

	// Telugu (te)
	LangTelugu ResourceLang = 0x004A
	// Telugu India (te-IN)
	SubLangTeluguIndia ResourceSubLang = 0x1

	// Thai (th)
	LangThai ResourceLang = 0x001E
	// Thai Thailand (th-TH)
	SubLangThaiThailand ResourceSubLang = 0x1

	// Tibetan (bo)
	LangTibetan ResourceLang = 0x0051
	// Tibetan People's Republic Of China (bo-CN)
	SubLangTibetanPeoplesRepublicOfChina ResourceSubLang = 0x1

	// Tigrinya (ti)
	LangTigrinya ResourceLang = 0x0073
	// Tigrinya Eritrea (ti-ER)
	SubLangTigrinyaEritrea ResourceSubLang = 0x2
	// Tigrinya Ethiopia (ti-ET)
	SubLangTigrinyaEthiopia ResourceSubLang = 0x1

	// Tsonga (ts)
	LangTsonga ResourceLang = 0x0031
	// Tsonga South Africa (ts-ZA)
	SubLangTsongaSouthAfrica ResourceSubLang = 0x1

	// Turkish (tr)
	LangTurkish ResourceLang = 0x001F
	// Turkish Turkey (tr-TR)
	SubLangTurkishTurkey ResourceSubLang = 0x1

	// Turkmen (tk)
	LangTurkmen ResourceLang = 0x0042
	// Turkmen Turkmenistan (tk-TM)
	SubLangTurkmenTurkmenistan ResourceSubLang = 0x1

	// Ukrainian (uk)
	LangUkrainian ResourceLang = 0x0022
	// Ukrainian Ukraine (uk-UA)
	SubLangUkrainianUkraine ResourceSubLang = 0x1

	// Upper Sorbian (hsb)
	LangUpperSorbian ResourceLang = 0x002E
	// Upper Sorbian Germany (hsb-DE)
	SubLangUpperSorbianGermany ResourceSubLang = 0x1

	// Urdu (ur)
	LangUrdu ResourceLang = 0x0020
	// Urdu India (ur-IN)
	SubLangUrduIndia ResourceSubLang = 0x2
	// Urdu Islamic Republic Of Pakistan (ur-PK)
	SubLangUrduIslamicRepublicOfPakistan ResourceSubLang = 0x1

	// Uyghur (ug)
	LangUyghur ResourceLang = 0x0080
	// Uyghur People's Republic Of China (ug-CN)
	SubLangUyghurPeoplesRepublicOfChina ResourceSubLang = 0x1
	// Uzbek (Cyrillic) (uz-Cyrl)
	SubLangUzbekCyrillic ResourceSubLang = 0x1e
	// Uzbek (Cyrillic) Uzbekistan (uz-Cyrl-UZ)
	SubLangUzbekCyrillicUzbekistan ResourceSubLang = 0x2

	// Uzbek (Latin) (uz)
	LangUzbekLatin ResourceLang = 0x0043
	// Uzbek (Latin) (uz-Latn)
	SubLangUzbekLatin ResourceSubLang = 0x1f
	// Uzbek (Latin) Uzbekistan (uz-Latn-UZ)
	SubLangUzbekLatinUzbekistan ResourceSubLang = 0x1
	// Valencian Spain (ca-ESvalencia)
	SubLangValencianSpain ResourceSubLang = 0x2

	// Venda (ve)
	LangVenda ResourceLang = 0x0033
	// Venda South Africa (ve-ZA)
	SubLangVendaSouthAfrica ResourceSubLang = 0x1

	// Vietnamese (vi)
	LangVietnamese ResourceLang = 0x002A
	// Vietnamese Vietnam (vi-VN)
	SubLangVietnameseVietnam ResourceSubLang = 0x1

	// Welsh (cy)
	LangWelsh ResourceLang = 0x0052
	// Welsh United Kingdom (cy-GB)
	SubLangWelshUnitedKingdom ResourceSubLang = 0x1

	// Wolof (wo)
	LangWolof ResourceLang = 0x0088
	// Wolof Senegal (wo-SN)
	SubLangWolofSenegal ResourceSubLang = 0x1

	// Xhosa (xh)
	LangXhosa ResourceLang = 0x0034
	// Xhosa South Africa (xh-ZA)
	SubLangXhosaSouthAfrica ResourceSubLang = 0x1

	// Yi (ii)
	LangYi ResourceLang = 0x0078
	// Yi People's Republic Of China (ii-CN)
	SubLangYiPeoplesRepublicOfChina ResourceSubLang = 0x1
	// Yiddish World (yi-001)
	SubLangYiddishWorld ResourceSubLang = 0x1

	// Yoruba (yo)
	LangYoruba ResourceLang = 0x006A
	// Yoruba Nigeria (yo-NG)
	SubLangYorubaNigeria ResourceSubLang = 0x1

	// Zulu (zu)
	LangZulu ResourceLang = 0x0035
	// Zulu South Africa (zu-ZA)
	SubLangZuluSouthAfrica ResourceSubLang = 0x1
)

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
		LangAfrikaans:         "Afrikaans (af)",
		LangAlbanian:          "Albanian (sq)",
		LangAlsatian:          "Alsatian (gsw)",
		LangAmharic:           "Amharic (am)",
		LangArabic:            "Arabic (ar)",
		LangArmenian:          "Armenian (hy)",
		LangAssamese:          "Assamese (as)",
		LangAzerbaijaniLatin:  "Azerbaijani (Latin) (az)",
		LangBangla:            "Bangla (bn)",
		LangBashkir:           "Bashkir (ba)",
		LangBasque:            "Basque (eu)",
		LangBelarusian:        "Belarusian (be)",
		LangBosnianLatin:      "Bosnian (Latin) (bs)",
		LangBreton:            "Breton (br)",
		LangBulgarian:         "Bulgarian (bg)",
		LangBurmese:           "Burmese (my)",
		LangCatalan:           "Catalan (ca)",
		LangCentralKurdish:    "Central Kurdish (ku)",
		LangCherokee:          "Cherokee (chr)",
		LangChineseSimplified: "Chinese (Simplified) (zh)",
		LangCorsican:          "Corsican (co)",
		LangCroatian:          "Croatian (hr)",
		LangCzech:             "Czech (cs)",
		LangDanish:            "Danish (da)",
		LangDari:              "Dari (prs)",
		LangDivehi:            "Divehi (dv)",
		LangDutch:             "Dutch (nl)",
		LangEnglish:           "English (en)",
		LangEstonian:          "Estonian (et)",
		LangFaroese:           "Faroese (fo)",
		LangFilipino:          "Filipino (fil)",
		LangFinnish:           "Finnish (fi)",
		LangFrench:            "French (fr)",
		LangFrisian:           "Frisian (fy)",
		LangFulah:             "Fulah (ff)",
		LangGalician:          "Galician (gl)",
		LangGeorgian:          "Georgian (ka)",
		LangGerman:            "German (de)",
		LangGreek:             "Greek (el)",
		LangGreenlandic:       "Greenlandic (kl)",
		LangGuarani:           "Guarani (gn)",
		LangGujarati:          "Gujarati (gu)",
		LangHausaLatin:        "Hausa (Latin) (ha)",
		LangHawaiian:          "Hawaiian (haw)",
		LangHebrew:            "Hebrew (he)",
		LangHindi:             "Hindi (hi)",
		LangHungarian:         "Hungarian (hu)",
		LangIcelandic:         "Icelandic (is)",
		LangIgbo:              "Igbo (ig)",
		LangIndonesian:        "Indonesian (id)",
		LangInuktitutLatin:    "Inuktitut (Latin) (iu)",
		LangIrish:             "Irish (ga)",
		LangItalian:           "Italian (it)",
		LangJapanese:          "Japanese (ja)",
		LangKannada:           "Kannada (kn)",
		LangKashmiri:          "Kashmiri (ks)",
		LangKazakh:            "Kazakh (kk)",
		LangKhmer:             "Khmer (km)",
		LangKiche:             "K'iche (quc)",
		LangKinyarwanda:       "Kinyarwanda (rw)",
		LangKiswahili:         "Kiswahili (sw)",
		LangKonkani:           "Konkani (kok)",
		LangKorean:            "Korean (ko)",
		LangKyrgyz:            "Kyrgyz (ky)",
		LangLao:               "Lao (lo)",
		LangLatvian:           "Latvian (lv)",
		LangLithuanian:        "Lithuanian (lt)",
		LangLowerSorbian:      "Lower Sorbian (dsb)",
		LangLuxembourgish:     "Luxembourgish (lb)",
		LangMacedonian:        "Macedonian (mk)",
		LangMalay:             "Malay (ms)",
		LangMalayalam:         "Malayalam (ml)",
		LangMaltese:           "Maltese (mt)",
		LangMaori:             "Maori (mi)",
		LangMapudungun:        "Mapudungun (arn)",
		LangMarathi:           "Marathi (mr)",
		LangMohawk:            "Mohawk (moh)",
		LangMongolianCyrillic: "Mongolian (Cyrillic) (mn)",
		LangNepali:            "Nepali (ne)",
		LangNorwegianBokmal:   "Norwegian (Bokmal) (no)",
		LangNorwegianBokmal:   "Norwegian (Bokmal) (nb)",
		LangNorwegianNynorsk:  "Norwegian (Nynorsk) (nn)",
		LangOccitan:           "Occitan (oc)",
		LangOdia:              "Odia (or)",
		LangOromo:             "Oromo (om)",
		LangPashto:            "Pashto (ps)",
		LangPersian:           "Persian (fa)",
		LangPolish:            "Polish (pl)",
		LangPortuguese:        "Portuguese (pt)",
		LangPunjabi:           "Punjabi (pa)",
		LangQuechua:           "Quechua (quz)",
		LangRomanian:          "Romanian (ro)",
		LangRomansh:           "Romansh (rm)",
		LangRussian:           "Russian (ru)",
		LangSakha:             "Sakha (sah)",
		LangSamiInari:         "Sami (Inari) (smn)",
		LangSamiLule:          "Sami (Lule) (smj)",
		LangSamiNorthern:      "Sami (Northern) (se)",
		LangSamiSkolt:         "Sami (Skolt) (sms)",
		LangSamiSouthern:      "Sami (Southern) (sma)",
		LangSanskrit:          "Sanskrit (sa)",
		LangScottishGaelic:    "Scottish Gaelic (gd)",
		LangSerbianLatin:      "Serbian (Latin) (sr)",
		LangSesothoSaLeboa:    "Sesotho Sa Leboa (nso)",
		LangSetswana:          "Setswana (tn)",
		LangSindhi:            "Sindhi (sd)",
		LangSinhala:           "Sinhala (si)",
		LangSlovak:            "Slovak (sk)",
		LangSlovenian:         "Slovenian (sl)",
		LangSomali:            "Somali (so)",
		LangSotho:             "Sotho (st)",
		LangSpanish:           "Spanish (es)",
		LangSwedish:           "Swedish (sv)",
		LangSyriac:            "Syriac (syr)",
		LangTajikCyrillic:     "Tajik (Cyrillic) (tg)",
		LangTamazightLatin:    "Tamazight (Latin) (tzm)",
		LangTamil:             "Tamil (ta)",
		LangTatar:             "Tatar (tt)",
		LangTelugu:            "Telugu (te)",
		LangThai:              "Thai (th)",
		LangTibetan:           "Tibetan (bo)",
		LangTigrinya:          "Tigrinya (ti)",
		LangTsonga:            "Tsonga (ts)",
		LangTurkish:           "Turkish (tr)",
		LangTurkmen:           "Turkmen (tk)",
		LangUkrainian:         "Ukrainian (uk)",
		LangUpperSorbian:      "Upper Sorbian (hsb)",
		LangUrdu:              "Urdu (ur)",
		LangUyghur:            "Uyghur (ug)",
		LangUzbekLatin:        "Uzbek (Latin) (uz)",
		LangVenda:             "Venda (ve)",
		LangVietnamese:        "Vietnamese (vi)",
		LangWelsh:             "Welsh (cy)",
		LangWolof:             "Wolof (wo)",
		LangXhosa:             "Xhosa (xh)",
		LangYi:                "Yi (ii)",
		LangYoruba:            "Yoruba (yo)",
		LangZulu:              "Zulu (zu)",
	}

	if val, ok := rsrcLangMap[lang]; ok {
		return val
	}

	return "?"
}

// String stringify the resource sub language.
func (subLang ResourceSubLang) String() string {

	rsrcSubLangMap := map[ResourceSubLang]string{
		SubLangAfrikaansSouthAfrica:                    "Afrikaans South Africa (af-ZA)",
		SubLangAlbanianAlbania:                         "Albanian Albania (sq-AL)",
		SubLangAlsatianFrance:                          "Alsatian France (gsw-FR)",
		SubLangAmharicEthiopia:                         "Amharic Ethiopia (am-ET)",
		SubLangArabicAlgeria:                           "Arabic Algeria (ar-DZ)",
		SubLangArabicBahrain:                           "Arabic Bahrain (ar-BH)",
		SubLangArabicEgypt:                             "Arabic Egypt (ar-EG)",
		SubLangArabicIraq:                              "Arabic Iraq (ar-IQ)",
		SubLangArabicJordan:                            "Arabic Jordan (ar-JO)",
		SubLangArabicKuwait:                            "Arabic Kuwait (ar-KW)",
		SubLangArabicLebanon:                           "Arabic Lebanon (ar-LB)",
		SubLangArabicLibya:                             "Arabic Libya (ar-LY)",
		SubLangArabicMorocco:                           "Arabic Morocco (ar-MA)",
		SubLangArabicOman:                              "Arabic Oman (ar-OM)",
		SubLangArabicQatar:                             "Arabic Qatar (ar-QA)",
		SubLangArabicSaudiArabia:                       "Arabic Saudi Arabia (ar-SA)",
		SubLangArabicSyria:                             "Arabic Syria (ar-SY)",
		SubLangArabicTunisia:                           "Arabic Tunisia (ar-TN)",
		SubLangArabicUae:                               "Arabic U.a.e. (ar-AE)",
		SubLangArabicYemen:                             "Arabic Yemen (ar-YE)",
		SubLangArmenianArmenia:                         "Armenian Armenia (hy-AM)",
		SubLangAssameseIndia:                           "Assamese India (as-IN)",
		SubLangAzerbaijaniCyrillic:                     "Azerbaijani (Cyrillic) (az-Cyrl)",
		SubLangAzerbaijaniCyrillicAzerbaijan:           "Azerbaijani (Cyrillic) Azerbaijan (az-Cyrl-AZ)",
		SubLangAzerbaijaniLatin:                        "Azerbaijani (Latin) (az-Latn)",
		SubLangAzerbaijaniLatinAzerbaijan:              "Azerbaijani (Latin) Azerbaijan (az-Latn-AZ)",
		SubLangBanglaBangladesh:                        "Bangla Bangladesh (bn-BD)",
		SubLangBanglaIndia:                             "Bangla India (bn-IN)",
		SubLangBashkirRussia:                           "Bashkir Russia (ba-RU)",
		SubLangBasqueSpain:                             "Basque Spain (eu-ES)",
		SubLangBelarusianBelarus:                       "Belarusian Belarus (be-BY)",
		SubLangBosnianCyrillic:                         "Bosnian (Cyrillic) (bs-Cyrl)",
		SubLangBosnianCyrillicBosniaAndHerzegovina:     "Bosnian (Cyrillic) Bosnia And Herzegovina (bs-Cyrl-BA)",
		SubLangBosnianLatin:                            "Bosnian (Latin) (bs-Latn)",
		SubLangBosnianLatinBosniaAndHerzegovina:        "Bosnian (Latin) Bosnia And Herzegovina (bs-Latn-BA)",
		SubLangBretonFrance:                            "Breton France (br-FR)",
		SubLangBulgarianBulgaria:                       "Bulgarian Bulgaria (bg-BG)",
		SubLangBurmeseMyanmar:                          "Burmese Myanmar (my-MM)",
		SubLangCatalanSpain:                            "Catalan Spain (ca-ES)",
		SubLangCentralKurdish:                          "Central Kurdish (ku-Arab)",
		SubLangCentralKurdishIraq:                      "Central Kurdish Iraq (ku-Arab-IQ)",
		SubLangCherokee:                                "Cherokee (chr-Cher)",
		SubLangCherokeeUnitedStates:                    "Cherokee United States (chr-Cher-US)",
		SubLangChineseSimplified:                       "Chinese (Simplified) (zh-Hans)",
		SubLangChineseSimplifiedPeoplesRepublicOfChina: "Chinese (Simplified) People's Republic Of China (zh-CN)",
		SubLangChineseSimplifiedSingapore:              "Chinese (Simplified) Singapore (zh-SG)",
		SubLangChineseTraditional:                      "Chinese (Traditional) (zh-Hant)",
		SubLangChineseTraditionalHongKongSar:           "Chinese (Traditional) Hong Kong S.a.r. (zh-HK)",
		SubLangChineseTraditionalMacaoSar:              "Chinese (Traditional) Macao S.a.r. (zh-MO)",
		SubLangChineseTraditionalTaiwan:                "Chinese (Traditional) Taiwan (zh-TW)",
		SubLangCorsicanFrance:                          "Corsican France (co-FR)",
		SubLangCroatianCroatia:                         "Croatian Croatia (hr-HR)",
		SubLangCroatianLatinBosniaAndHerzegovina:       "Croatian (Latin) Bosnia And Herzegovina (hr-BA)",
		SubLangCzechCzechRepublic:                      "Czech Czech Republic (cs-CZ)",
		SubLangDanishDenmark:                           "Danish Denmark (da-DK)",
		SubLangDariAfghanistan:                         "Dari Afghanistan (prs-AF)",
		SubLangDivehiMaldives:                          "Divehi Maldives (dv-MV)",
		SubLangDutchBelgium:                            "Dutch Belgium (nl-BE)",
		SubLangDutchNetherlands:                        "Dutch Netherlands (nl-NL)",
		SubLangDzongkhaBhutan:                          "Dzongkha Bhutan (dz-BT)",
		SubLangEnglishAustralia:                        "English Australia (en-AU)",
		SubLangEnglishBelize:                           "English Belize (en-BZ)",
		SubLangEnglishCanada:                           "English Canada (en-CA)",
		SubLangEnglishCaribbean:                        "English Caribbean (en-029)",
		SubLangEnglishHongKong:                         "English Hong Kong (en-HK)",
		SubLangEnglishIndia:                            "English India (en-IN)",
		SubLangEnglishIreland:                          "English Ireland (en-IE)",
		SubLangEnglishJamaica:                          "English Jamaica (en-JM)",
		SubLangEnglishMalaysia:                         "English Malaysia (en-MY)",
		SubLangEnglishNewZealand:                       "English New Zealand (en-NZ)",
		SubLangEnglishRepublicOfThePhilippines:         "English Republic Of The Philippines (en-PH)",
		SubLangEnglishSingapore:                        "English Singapore (en-SG)",
		SubLangEnglishSouthAfrica:                      "English South Africa (en-ZA)",
		SubLangEnglishTrinidadAndTobago:                "English Trinidad And Tobago (en-TT)",
		SubLangEnglishUnitedArabEmirates:               "English United Arab Emirates (en-AE)",
		SubLangEnglishUnitedKingdom:                    "English United Kingdom (en-GB)",
		SubLangEnglishUnitedStates:                     "English United States (en-US)",
		SubLangEnglishZimbabwe:                         "English Zimbabwe (en-ZW)",
		SubLangEstonianEstonia:                         "Estonian Estonia (et-EE)",
		SubLangFaroeseFaroeIslands:                     "Faroese Faroe Islands (fo-FO)",
		SubLangFilipinoPhilippines:                     "Filipino Philippines (fil-PH)",
		SubLangFinnishFinland:                          "Finnish Finland (fi-FI)",
		SubLangFrenchBelgium:                           "French Belgium (fr-BE)",
		SubLangFrenchCameroon:                          "French Cameroon (fr-CM)",
		SubLangFrenchCanada:                            "French Canada (fr-CA)",
		SubLangFrenchCaribbean:                         "French Caribbean (fr-029)",
		SubLangFrenchCongoDrc:                          "French Congo, Drc (fr-CD)",
		SubLangFrenchCôteDivoire:                       "French Côte D'ivoire (fr-CI)",
		SubLangFrenchFrance:                            "French France (fr-FR)",
		SubLangFrenchHaiti:                             "French Haiti (fr-HT)",
		SubLangFrenchLuxembourg:                        "French Luxembourg (fr-LU)",
		SubLangFrenchMali:                              "French Mali (fr-ML)",
		SubLangFrenchMorocco:                           "French Morocco (fr-MA)",
		SubLangFrenchPrincipalityOfMonaco:              "French Principality Of Monaco (fr-MC)",
		SubLangFrenchReunion:                           "French Reunion (fr-RE)",
		SubLangFrenchSenegal:                           "French Senegal (fr-SN)",
		SubLangFrenchSwitzerland:                       "French Switzerland (fr-CH)",
		SubLangFrisianNetherlands:                      "Frisian Netherlands (fy-NL)",
		SubLangFulahLatin:                              "Fulah (Latin) (ff-Latn)",
		SubLangFulahNigeria:                            "Fulah Nigeria (ff-NG)",
		SubLangFulahLatinNigeria:                       "Fulah (Latin) Nigeria (ff-Latn-NG)",
		SubLangFulahSenegal:                            "Fulah Senegal (ff-Latn-SN)",
		SubLangGalicianSpain:                           "Galician Spain (gl-ES)",
		SubLangGeorgianGeorgia:                         "Georgian Georgia (ka-GE)",
		SubLangGermanAustria:                           "German Austria (de-AT)",
		SubLangGermanGermany:                           "German Germany (de-DE)",
		SubLangGermanLiechtenstein:                     "German Liechtenstein (de-LI)",
		SubLangGermanLuxembourg:                        "German Luxembourg (de-LU)",
		SubLangGermanSwitzerland:                       "German Switzerland (de-CH)",
		SubLangGreekGreece:                             "Greek Greece (el-GR)",
		SubLangGreenlandicGreenland:                    "Greenlandic Greenland (kl-GL)",
		SubLangGuaraniParaguay:                         "Guarani Paraguay (gn-PY)",
		SubLangGujaratiIndia:                           "Gujarati India (gu-IN)",
		SubLangHausaLatin:                              "Hausa (Latin) (ha-Latn)",
		SubLangHausaLatinNigeria:                       "Hausa (Latin) Nigeria (ha-Latn-NG)",
		SubLangHawaiianUnitedStates:                    "Hawaiian United States (haw-US)",
		SubLangHebrewIsrael:                            "Hebrew Israel (he-IL)",
		SubLangHindiIndia:                              "Hindi India (hi-IN)",
		SubLangHungarianHungary:                        "Hungarian Hungary (hu-HU)",
		SubLangIcelandicIceland:                        "Icelandic Iceland (is-IS)",
		SubLangIgboNigeria:                             "Igbo Nigeria (ig-NG)",
		SubLangIndonesianIndonesia:                     "Indonesian Indonesia (id-ID)",
		SubLangInuktitutLatin:                          "Inuktitut (Latin) (iu-Latn)",
		SubLangInuktitutLatinCanada:                    "Inuktitut (Latin) Canada (iu-Latn-CA)",
		SubLangInuktitutSyllabics:                      "Inuktitut (Syllabics) (iu-Cans)",
		SubLangInuktitutSyllabicsCanada:                "Inuktitut (Syllabics) Canada (iu-Cans-CA)",
		SubLangIrishIreland:                            "Irish Ireland (ga-IE)",
		SubLangItalianItaly:                            "Italian Italy (it-IT)",
		SubLangItalianSwitzerland:                      "Italian Switzerland (it-CH)",
		SubLangJapaneseJapan:                           "Japanese Japan (ja-JP)",
		SubLangKannadaIndia:                            "Kannada India (kn-IN)",
		SubLangKanuriLatinNigeria:                      "Kanuri (Latin) Nigeria (kr-Latn-NG)",
		SubLangKashmiriPersoArabic:                     "Kashmiri Perso-Arabic (ks-Arab)",
		SubLangKashmiriDevanagariIndia:                 "Kashmiri (Devanagari) India (ks-Deva-IN)",
		SubLangKazakhKazakhstan:                        "Kazakh Kazakhstan (kk-KZ)",
		SubLangKhmerCambodia:                           "Khmer Cambodia (km-KH)",
		SubLangKicheGuatemala:                          "K'iche Guatemala (quc-Latn-GT)",
		SubLangKinyarwandaRwanda:                       "Kinyarwanda Rwanda (rw-RW)",
		SubLangKiswahiliKenya:                          "Kiswahili Kenya (sw-KE)",
		SubLangKonkaniIndia:                            "Konkani India (kok-IN)",
		SubLangKoreanKorea:                             "Korean Korea (ko-KR)",
		SubLangKyrgyzKyrgyzstan:                        "Kyrgyz Kyrgyzstan (ky-KG)",
		SubLangLaoLaoPdr:                               "Lao Lao P.d.r. (lo-LA)",
		SubLangLatinVaticanCity:                        "Latin Vatican City (la-VA)",
		SubLangLatvianLatvia:                           "Latvian Latvia (lv-LV)",
		SubLangLithuanianLithuania:                     "Lithuanian Lithuania (lt-LT)",
		SubLangLowerSorbianGermany:                     "Lower Sorbian Germany (dsb-DE)",
		SubLangLuxembourgishLuxembourg:                 "Luxembourgish Luxembourg (lb-LU)",
		SubLangMacedonianNorthMacedonia:                "Macedonian North Macedonia (mk-MK)",
		SubLangMalayBruneiDarussalam:                   "Malay Brunei Darussalam (ms-BN)",
		SubLangMalayMalaysia:                           "Malay Malaysia (ms-MY)",
		SubLangMalayalamIndia:                          "Malayalam India (ml-IN)",
		SubLangMalteseMalta:                            "Maltese Malta (mt-MT)",
		SubLangMaoriNewZealand:                         "Maori New Zealand (mi-NZ)",
		SubLangMapudungunChile:                         "Mapudungun Chile (arn-CL)",
		SubLangMarathiIndia:                            "Marathi India (mr-IN)",
		SubLangMohawkCanada:                            "Mohawk Canada (moh-CA)",
		SubLangMongolianCyrillic:                       "Mongolian (Cyrillic) (mn-Cyrl)",
		SubLangMongolianCyrillicMongolia:               "Mongolian (Cyrillic) Mongolia (mn-MN)",
		SubLangMongolianTraditionalMongolian:           "Mongolian (Traditional Mongolian) (mn-Mong)",
		SubLangMongolianTraditionalMongolianPeoplesRepublicOfChina: "Mongolian (Traditional Mongolian) People's Republic Of China (mn-MongCN)",
		SubLangMongolianTraditionalMongolianMongolia:               "Mongolian (Traditional Mongolian) Mongolia (mn-MongMN)",
		SubLangNepaliIndia:            "Nepali India (ne-IN)",
		SubLangNepaliNepal:            "Nepali Nepal (ne-NP)",
		SubLangNorwegianBokmalNorway:  "Norwegian (Bokmal) Norway (nb-NO)",
		SubLangNorwegianNynorskNorway: "Norwegian (Nynorsk) Norway (nn-NO)",
		SubLangOccitanFrance:          "Occitan France (oc-FR)",
		SubLangOdiaIndia:              "Odia India (or-IN)",
		SubLangOromoEthiopia:          "Oromo Ethiopia (om-ET)",
		SubLangPashtoAfghanistan:      "Pashto Afghanistan (ps-AF)",
		SubLangPersianIran:            "Persian Iran (fa-IR)",
		SubLangPolishPoland:           "Polish Poland (pl-PL)",
		SubLangPortugueseBrazil:       "Portuguese Brazil (pt-BR)",
		SubLangPortuguesePortugal:     "Portuguese Portugal (pt-PT)",
		SubLangPseudoLanguagePseudoLocaleForEastAsianComplexScriptLocalizationTesting: "Pseudo Language Pseudo Locale For East Asian/Complex Script Localization Testing (qps-ploca)",
		SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTesting:                   "Pseudo Language Pseudo Locale Used For Localization Testing (qps-ploc)",
		SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTestingOfMirroredLocales:  "Pseudo Language Pseudo Locale Used For Localization Testing Of Mirrored Locales (qps-plocm)",
		SubLangPunjabi:                                  "Punjabi (pa-Arab)",
		SubLangPunjabiIndia:                             "Punjabi India (pa-IN)",
		SubLangPunjabiIslamicRepublicOfPakistan:         "Punjabi Islamic Republic Of Pakistan (pa-Arab-PK)",
		SubLangQuechuaBolivia:                           "Quechua Bolivia (quz-BO)",
		SubLangQuechuaEcuador:                           "Quechua Ecuador (quz-EC)",
		SubLangQuechuaPeru:                              "Quechua Peru (quz-PE)",
		SubLangRomanianMoldova:                          "Romanian Moldova (ro-MD)",
		SubLangRomanianRomania:                          "Romanian Romania (ro-RO)",
		SubLangRomanshSwitzerland:                       "Romansh Switzerland (rm-CH)",
		SubLangRussianMoldova:                           "Russian Moldova (ru-MD)",
		SubLangRussianRussia:                            "Russian Russia (ru-RU)",
		SubLangSakhaRussia:                              "Sakha Russia (sah-RU)",
		SubLangSamiInariFinland:                         "Sami (Inari) Finland (smn-FI)",
		SubLangSamiLuleNorway:                           "Sami (Lule) Norway (smj-NO)",
		SubLangSamiLuleSweden:                           "Sami (Lule) Sweden (smj-SE)",
		SubLangSamiNorthernFinland:                      "Sami (Northern) Finland (se-FI)",
		SubLangSamiNorthernNorway:                       "Sami (Northern) Norway (se-NO)",
		SubLangSamiNorthernSweden:                       "Sami (Northern) Sweden (se-SE)",
		SubLangSamiSkoltFinland:                         "Sami (Skolt) Finland (sms-FI)",
		SubLangSamiSouthernNorway:                       "Sami (Southern) Norway (sma-NO)",
		SubLangSamiSouthernSweden:                       "Sami (Southern) Sweden (sma-SE)",
		SubLangSanskritIndia:                            "Sanskrit India (sa-IN)",
		SubLangScottishGaelicUnitedKingdom:              "Scottish Gaelic United Kingdom (gd-GB)",
		SubLangSerbianCyrillic:                          "Serbian (Cyrillic) (sr-Cyrl)",
		SubLangSerbianCyrillicBosniaAndHerzegovina:      "Serbian (Cyrillic) Bosnia And Herzegovina (sr-Cyrl-BA)",
		SubLangSerbianCyrillicMontenegro:                "Serbian (Cyrillic) Montenegro (sr-Cyrl-ME)",
		SubLangSerbianCyrillicSerbia:                    "Serbian (Cyrillic) Serbia (sr-Cyrl-RS)",
		SubLangSerbianCyrillicSerbiaAndMontenegroFormer: "Serbian (Cyrillic) Serbia And Montenegro (former) (sr-Cyrl-CS)",
		SubLangSerbianLatin:                             "Serbian (Latin) (sr-Latn)",
		SubLangSerbianLatinBosniaAndHerzegovina:         "Serbian (Latin) Bosnia And Herzegovina (sr-Latn-BA)",
		SubLangSerbianLatinMontenegro:                   "Serbian (Latin) Montenegro (sr-Latn-ME)",
		SubLangSerbianLatinSerbia:                       "Serbian (Latin) Serbia (sr-Latn-RS)",
		SubLangSerbianLatinSerbiaAndMontenegroFormer:    "Serbian (Latin) Serbia And Montenegro (former) (sr-Latn-CS)",
		SubLangSesothoSaLeboaSouthAfrica:                "Sesotho Sa Leboa South Africa (nso-ZA)",
		SubLangSetswanaBotswana:                         "Setswana Botswana (tn-BW)",
		SubLangSetswanaSouthAfrica:                      "Setswana South Africa (tn-ZA)",
		SubLangSindhi:                                   "Sindhi (sd-Arab)",
		SubLangSindhiIslamicRepublicOfPakistan:          "Sindhi Islamic Republic Of Pakistan (sd-Arab-PK)",
		SubLangSinhalaSriLanka:                          "Sinhala Sri Lanka (si-LK)",
		SubLangSlovakSlovakia:                           "Slovak Slovakia (sk-SK)",
		SubLangSlovenianSlovenia:                        "Slovenian Slovenia (sl-SI)",
		SubLangSomaliSomalia:                            "Somali Somalia (so-SO)",
		SubLangSothoSouthAfrica:                         "Sotho South Africa (st-ZA)",
		SubLangSpanishArgentina:                         "Spanish Argentina (es-AR)",
		SubLangSpanishBolivarianRepublicOfVenezuela:     "Spanish Bolivarian Republic Of Venezuela (es-VE)",
		SubLangSpanishBolivia:                           "Spanish Bolivia (es-BO)",
		SubLangSpanishChile:                             "Spanish Chile (es-CL)",
		SubLangSpanishColombia:                          "Spanish Colombia (es-CO)",
		SubLangSpanishCostaRica:                         "Spanish Costa Rica (es-CR)",
		SubLangSpanishCuba:                              "Spanish Cuba (es-CU)",
		SubLangSpanishDominicanRepublic:                 "Spanish Dominican Republic (es-DO)",
		SubLangSpanishEcuador:                           "Spanish Ecuador (es-EC)",
		SubLangSpanishElSalvador:                        "Spanish El Salvador (es-SV)",
		SubLangSpanishGuatemala:                         "Spanish Guatemala (es-GT)",
		SubLangSpanishHonduras:                          "Spanish Honduras (es-HN)",
		SubLangSpanishLatinAmerica:                      "Spanish Latin America (es-419)",
		SubLangSpanishMexico:                            "Spanish Mexico (es-MX)",
		SubLangSpanishNicaragua:                         "Spanish Nicaragua (es-NI)",
		SubLangSpanishPanama:                            "Spanish Panama (es-PA)",
		SubLangSpanishParaguay:                          "Spanish Paraguay (es-PY)",
		SubLangSpanishPeru:                              "Spanish Peru (es-PE)",
		SubLangSpanishPuertoRico:                        "Spanish Puerto Rico (es-PR)",
		SubLangSpanishSpain:                             "Spanish Spain (es-ES_tradnl)",
		SubLangSpanishSpain:                             "Spanish Spain (es-ES)",
		SubLangSpanishUnitedStates:                      "Spanish United States (es-US)",
		SubLangSpanishUruguay:                           "Spanish Uruguay (es-UY)",
		SubLangSwedishFinland:                           "Swedish Finland (sv-FI)",
		SubLangSwedishSweden:                            "Swedish Sweden (sv-SE)",
		SubLangSyriacSyria:                              "Syriac Syria (syr-SY)",
		SubLangTajikCyrillic:                            "Tajik (Cyrillic) (tg-Cyrl)",
		SubLangTajikCyrillicTajikistan:                  "Tajik (Cyrillic) Tajikistan (tg-Cyrl-TJ)",
		SubLangTamazightLatin:                           "Tamazight (Latin) (tzm-Latn)",
		SubLangTamazightLatinAlgeria:                    "Tamazight (Latin) Algeria (tzm-Latn-DZ)",
		SubLangTamilIndia:                               "Tamil India (ta-IN)",
		SubLangTamilSriLanka:                            "Tamil Sri Lanka (ta-LK)",
		SubLangTatarRussia:                              "Tatar Russia (tt-RU)",
		SubLangTeluguIndia:                              "Telugu India (te-IN)",
		SubLangThaiThailand:                             "Thai Thailand (th-TH)",
		SubLangTibetanPeoplesRepublicOfChina:            "Tibetan People's Republic Of China (bo-CN)",
		SubLangTigrinyaEritrea:                          "Tigrinya Eritrea (ti-ER)",
		SubLangTigrinyaEthiopia:                         "Tigrinya Ethiopia (ti-ET)",
		SubLangTsongaSouthAfrica:                        "Tsonga South Africa (ts-ZA)",
		SubLangTurkishTurkey:                            "Turkish Turkey (tr-TR)",
		SubLangTurkmenTurkmenistan:                      "Turkmen Turkmenistan (tk-TM)",
		SubLangUkrainianUkraine:                         "Ukrainian Ukraine (uk-UA)",
		SubLangUpperSorbianGermany:                      "Upper Sorbian Germany (hsb-DE)",
		SubLangUrduIndia:                                "Urdu India (ur-IN)",
		SubLangUrduIslamicRepublicOfPakistan:            "Urdu Islamic Republic Of Pakistan (ur-PK)",
		SubLangUyghurPeoplesRepublicOfChina:             "Uyghur People's Republic Of China (ug-CN)",
		SubLangUzbekCyrillic:                            "Uzbek (Cyrillic) (uz-Cyrl)",
		SubLangUzbekCyrillicUzbekistan:                  "Uzbek (Cyrillic) Uzbekistan (uz-Cyrl-UZ)",
		SubLangUzbekLatin:                               "Uzbek (Latin) (uz-Latn)",
		SubLangUzbekLatinUzbekistan:                     "Uzbek (Latin) Uzbekistan (uz-Latn-UZ)",
		SubLangValencianSpain:                           "Valencian Spain (ca-ESvalencia)",
		SubLangVendaSouthAfrica:                         "Venda South Africa (ve-ZA)",
		SubLangVietnameseVietnam:                        "Vietnamese Vietnam (vi-VN)",
		SubLangWelshUnitedKingdom:                       "Welsh United Kingdom (cy-GB)",
		SubLangWolofSenegal:                             "Wolof Senegal (wo-SN)",
		SubLangXhosaSouthAfrica:                         "Xhosa South Africa (xh-ZA)",
		SubLangYiPeoplesRepublicOfChina:                 "Yi People's Republic Of China (ii-CN)",
		SubLangYiddishWorld:                             "Yiddish World (yi-001)",
		SubLangYorubaNigeria:                            "Yoruba Nigeria (yo-NG)",
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
		LangAfrikaans: {
			0x1: SubLangAfrikaansSouthAfrica,
		},
		LangAlbanian: {
			0x1: SubLangAlbanianAlbania,
		},
		LangAlsatian: {
			0x1: SubLangAlsatianFrance,
		},
		LangAmharic: {
			0x1: SubLangAmharicEthiopia,
		},
		LangArabic: {
			0x5:  SubLangArabicAlgeria,
			0xf:  SubLangArabicBahrain,
			0x3:  SubLangArabicEgypt,
			0x2:  SubLangArabicIraq,
			0xb:  SubLangArabicJordan,
			0xd:  SubLangArabicKuwait,
			0xc:  SubLangArabicLebanon,
			0x4:  SubLangArabicLibya,
			0x6:  SubLangArabicMorocco,
			0x8:  SubLangArabicOman,
			0x10: SubLangArabicQatar,
			0x1:  SubLangArabicSaudiArabia,
			0xa:  SubLangArabicSyria,
			0x7:  SubLangArabicTunisia,
			0xe:  SubLangArabicUae,
			0x9:  SubLangArabicYemen,
		},
		LangArmenian: {
			0x1: SubLangArmenianArmenia,
		},
		LangAssamese: {
			0x1:  SubLangAssameseIndia,
			0x1d: SubLangAzerbaijaniCyrillic,
			0x2:  SubLangAzerbaijaniCyrillicAzerbaijan,
		},
		LangAzerbaijaniLatin: {
			0x1e: SubLangAzerbaijaniLatin,
			0x1:  SubLangAzerbaijaniLatinAzerbaijan,
		},
		LangBangla: {
			0x2: SubLangBanglaBangladesh,
			0x1: SubLangBanglaIndia,
		},
		LangBashkir: {
			0x1: SubLangBashkirRussia,
		},
		LangBasque: {
			0x1: SubLangBasqueSpain,
		},
		LangBelarusian: {
			0x1:  SubLangBelarusianBelarus,
			0x19: SubLangBosnianCyrillic,
			0x8:  SubLangBosnianCyrillicBosniaAndHerzegovina,
			0x1a: SubLangBosnianLatin,
		},
		LangBosnianLatin: {
			0x5: SubLangBosnianLatinBosniaAndHerzegovina,
		},
		LangBreton: {
			0x1: SubLangBretonFrance,
		},
		LangBulgarian: {
			0x1: SubLangBulgarianBulgaria,
		},
		LangBurmese: {
			0x1: SubLangBurmeseMyanmar,
		},
		LangCatalan: {
			0x1: SubLangCatalanSpain,
		},
		LangCentralKurdish: {
			0x1f: SubLangCentralKurdish,
			0x1:  SubLangCentralKurdishIraq,
		},
		LangCherokee: {
			0x1f: SubLangCherokee,
			0x1:  SubLangCherokeeUnitedStates,
			0x0:  SubLangChineseSimplified,
		},
		LangChineseSimplified: {
			0x2:  SubLangChineseSimplifiedPeoplesRepublicOfChina,
			0x4:  SubLangChineseSimplifiedSingapore,
			0x1f: SubLangChineseTraditional,
			0x3:  SubLangChineseTraditionalHongKongSar,
			0x5:  SubLangChineseTraditionalMacaoSar,
			0x1:  SubLangChineseTraditionalTaiwan,
		},
		LangCorsican: {
			0x1: SubLangCorsicanFrance,
		},
		LangCroatian: {
			0x1: SubLangCroatianCroatia,
			0x4: SubLangCroatianLatinBosniaAndHerzegovina,
		},
		LangCzech: {
			0x1: SubLangCzechCzechRepublic,
		},
		LangDanish: {
			0x1: SubLangDanishDenmark,
		},
		LangDari: {
			0x1: SubLangDariAfghanistan,
		},
		LangDivehi: {
			0x1: SubLangDivehiMaldives,
		},
		LangDutch: {
			0x2: SubLangDutchBelgium,
			0x1: SubLangDutchNetherlands,
			0x3: SubLangDzongkhaBhutan,
		},
		LangEnglish: {
			0x3:  SubLangEnglishAustralia,
			0xa:  SubLangEnglishBelize,
			0x4:  SubLangEnglishCanada,
			0x9:  SubLangEnglishCaribbean,
			0xf:  SubLangEnglishHongKong,
			0x10: SubLangEnglishIndia,
			0x6:  SubLangEnglishIreland,
			0x8:  SubLangEnglishJamaica,
			0x11: SubLangEnglishMalaysia,
			0x5:  SubLangEnglishNewZealand,
			0xd:  SubLangEnglishRepublicOfThePhilippines,
			0x12: SubLangEnglishSingapore,
			0x7:  SubLangEnglishSouthAfrica,
			0xb:  SubLangEnglishTrinidadAndTobago,
			0x13: SubLangEnglishUnitedArabEmirates,
			0x2:  SubLangEnglishUnitedKingdom,
			0x1:  SubLangEnglishUnitedStates,
			0xc:  SubLangEnglishZimbabwe,
		},
		LangEstonian: {
			0x1: SubLangEstonianEstonia,
		},
		LangFaroese: {
			0x1: SubLangFaroeseFaroeIslands,
		},
		LangFilipino: {
			0x1: SubLangFilipinoPhilippines,
		},
		LangFinnish: {
			0x1: SubLangFinnishFinland,
		},
		LangFrench: {
			0x2: SubLangFrenchBelgium,
			0xb: SubLangFrenchCameroon,
			0x3: SubLangFrenchCanada,
			0x7: SubLangFrenchCaribbean,
			0x9: SubLangFrenchCongoDrc,
			0xc: SubLangFrenchCôteDivoire,
			0x1: SubLangFrenchFrance,
			0xf: SubLangFrenchHaiti,
			0x5: SubLangFrenchLuxembourg,
			0xd: SubLangFrenchMali,
			0xe: SubLangFrenchMorocco,
			0x6: SubLangFrenchPrincipalityOfMonaco,
			0x8: SubLangFrenchReunion,
			0xa: SubLangFrenchSenegal,
			0x4: SubLangFrenchSwitzerland,
		},
		LangFrisian: {
			0x1: SubLangFrisianNetherlands,
		},
		LangFulah: {
			0x1f: SubLangFulahLatin,
			0x1:  SubLangFulahNigeria,
			0x1:  SubLangFulahLatinNigeria,
			0x2:  SubLangFulahSenegal,
		},
		LangGalician: {
			0x1: SubLangGalicianSpain,
		},
		LangGeorgian: {
			0x1: SubLangGeorgianGeorgia,
		},
		LangGerman: {
			0x3: SubLangGermanAustria,
			0x1: SubLangGermanGermany,
			0x5: SubLangGermanLiechtenstein,
			0x4: SubLangGermanLuxembourg,
			0x2: SubLangGermanSwitzerland,
		},
		LangGreek: {
			0x1: SubLangGreekGreece,
		},
		LangGreenlandic: {
			0x1: SubLangGreenlandicGreenland,
		},
		LangGuarani: {
			0x1: SubLangGuaraniParaguay,
		},
		LangGujarati: {
			0x1: SubLangGujaratiIndia,
		},
		LangHausaLatin: {
			0x1f: SubLangHausaLatin,
			0x1:  SubLangHausaLatinNigeria,
		},
		LangHawaiian: {
			0x1: SubLangHawaiianUnitedStates,
		},
		LangHebrew: {
			0x1: SubLangHebrewIsrael,
		},
		LangHindi: {
			0x1: SubLangHindiIndia,
		},
		LangHungarian: {
			0x1: SubLangHungarianHungary,
		},
		LangIcelandic: {
			0x1: SubLangIcelandicIceland,
		},
		LangIgbo: {
			0x1: SubLangIgboNigeria,
		},
		LangIndonesian: {
			0x1: SubLangIndonesianIndonesia,
		},
		LangInuktitutLatin: {
			0x1f: SubLangInuktitutLatin,
			0x2:  SubLangInuktitutLatinCanada,
			0x1e: SubLangInuktitutSyllabics,
			0x1:  SubLangInuktitutSyllabicsCanada,
		},
		LangIrish: {
			0x2: SubLangIrishIreland,
		},
		LangItalian: {
			0x1: SubLangItalianItaly,
			0x2: SubLangItalianSwitzerland,
		},
		LangJapanese: {
			0x1: SubLangJapaneseJapan,
		},
		LangKannada: {
			0x1: SubLangKannadaIndia,
			0x1: SubLangKanuriLatinNigeria,
		},
		LangKashmiri: {
			0x1: SubLangKashmiriPersoArabic,
			0x2: SubLangKashmiriDevanagariIndia,
		},
		LangKazakh: {
			0x1: SubLangKazakhKazakhstan,
		},
		LangKhmer: {
			0x1: SubLangKhmerCambodia,
		},
		LangKiche: {
			0x1: SubLangKicheGuatemala,
		},
		LangKinyarwanda: {
			0x1: SubLangKinyarwandaRwanda,
		},
		LangKiswahili: {
			0x1: SubLangKiswahiliKenya,
		},
		LangKonkani: {
			0x1: SubLangKonkaniIndia,
		},
		LangKorean: {
			0x1: SubLangKoreanKorea,
		},
		LangKyrgyz: {
			0x1: SubLangKyrgyzKyrgyzstan,
		},
		LangLao: {
			0x1: SubLangLaoLaoPdr,
			0x1: SubLangLatinVaticanCity,
		},
		LangLatvian: {
			0x1: SubLangLatvianLatvia,
		},
		LangLithuanian: {
			0x1: SubLangLithuanianLithuania,
		},
		LangLowerSorbian: {
			0x2: SubLangLowerSorbianGermany,
		},
		LangLuxembourgish: {
			0x1: SubLangLuxembourgishLuxembourg,
		},
		LangMacedonian: {
			0x1: SubLangMacedonianNorthMacedonia,
		},
		LangMalay: {
			0x2: SubLangMalayBruneiDarussalam,
			0x1: SubLangMalayMalaysia,
		},
		LangMalayalam: {
			0x1: SubLangMalayalamIndia,
		},
		LangMaltese: {
			0x1: SubLangMalteseMalta,
		},
		LangMaori: {
			0x1: SubLangMaoriNewZealand,
		},
		LangMapudungun: {
			0x1: SubLangMapudungunChile,
		},
		LangMarathi: {
			0x1: SubLangMarathiIndia,
		},
		LangMohawk: {
			0x1: SubLangMohawkCanada,
		},
		LangMongolianCyrillic: {
			0x1e: SubLangMongolianCyrillic,
			0x1:  SubLangMongolianCyrillicMongolia,
			0x1f: SubLangMongolianTraditionalMongolian,
			0x2:  SubLangMongolianTraditionalMongolianPeoplesRepublicOfChina,
			0x3:  SubLangMongolianTraditionalMongolianMongolia,
		},
		LangNepali: {
			0x2: SubLangNepaliIndia,
			0x1: SubLangNepaliNepal,
		},
		LangNorwegianBokmal: {},
		LangNorwegianBokmal: {
			0x1: SubLangNorwegianBokmalNorway,
		},
		LangNorwegianNynorsk: {
			0x2: SubLangNorwegianNynorskNorway,
		},
		LangOccitan: {
			0x1: SubLangOccitanFrance,
		},
		LangOdia: {
			0x1: SubLangOdiaIndia,
		},
		LangOromo: {
			0x1: SubLangOromoEthiopia,
		},
		LangPashto: {
			0x1: SubLangPashtoAfghanistan,
		},
		LangPersian: {
			0x1: SubLangPersianIran,
		},
		LangPolish: {
			0x1: SubLangPolishPoland,
		},
		LangPortuguese: {
			0x1: SubLangPortugueseBrazil,
			0x2: SubLangPortuguesePortugal,
			0x1: SubLangPseudoLanguagePseudoLocaleForEastAsianComplexScriptLocalizationTesting,
			0x1: SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTesting,
			0x2: SubLangPseudoLanguagePseudoLocaleUsedForLocalizationTestingOfMirroredLocales,
		},
		LangPunjabi: {
			0x1f: SubLangPunjabi,
			0x1:  SubLangPunjabiIndia,
			0x2:  SubLangPunjabiIslamicRepublicOfPakistan,
		},
		LangQuechua: {
			0x1: SubLangQuechuaBolivia,
			0x2: SubLangQuechuaEcuador,
			0x3: SubLangQuechuaPeru,
		},
		LangRomanian: {
			0x2: SubLangRomanianMoldova,
			0x1: SubLangRomanianRomania,
		},
		LangRomansh: {
			0x1: SubLangRomanshSwitzerland,
		},
		LangRussian: {
			0x2: SubLangRussianMoldova,
			0x1: SubLangRussianRussia,
		},
		LangSakha: {
			0x1: SubLangSakhaRussia,
		},
		LangSamiInari: {
			0x9: SubLangSamiInariFinland,
		},
		LangSamiLule: {
			0x4: SubLangSamiLuleNorway,
			0x5: SubLangSamiLuleSweden,
		},
		LangSamiNorthern: {
			0x3: SubLangSamiNorthernFinland,
			0x1: SubLangSamiNorthernNorway,
			0x2: SubLangSamiNorthernSweden,
		},
		LangSamiSkolt: {
			0x8: SubLangSamiSkoltFinland,
		},
		LangSamiSouthern: {
			0x6: SubLangSamiSouthernNorway,
			0x7: SubLangSamiSouthernSweden,
		},
		LangSanskrit: {
			0x1: SubLangSanskritIndia,
		},
		LangScottishGaelic: {
			0x1:  SubLangScottishGaelicUnitedKingdom,
			0x1b: SubLangSerbianCyrillic,
			0x7:  SubLangSerbianCyrillicBosniaAndHerzegovina,
			0xc:  SubLangSerbianCyrillicMontenegro,
			0xa:  SubLangSerbianCyrillicSerbia,
			0x3:  SubLangSerbianCyrillicSerbiaAndMontenegroFormer,
			0x1c: SubLangSerbianLatin,
		},
		LangSerbianLatin: {
			0x6: SubLangSerbianLatinBosniaAndHerzegovina,
			0xb: SubLangSerbianLatinMontenegro,
			0x9: SubLangSerbianLatinSerbia,
			0x2: SubLangSerbianLatinSerbiaAndMontenegroFormer,
		},
		LangSesothoSaLeboa: {
			0x1: SubLangSesothoSaLeboaSouthAfrica,
		},
		LangSetswana: {
			0x2: SubLangSetswanaBotswana,
			0x1: SubLangSetswanaSouthAfrica,
		},
		LangSindhi: {
			0x1f: SubLangSindhi,
			0x2:  SubLangSindhiIslamicRepublicOfPakistan,
		},
		LangSinhala: {
			0x1: SubLangSinhalaSriLanka,
		},
		LangSlovak: {
			0x1: SubLangSlovakSlovakia,
		},
		LangSlovenian: {
			0x1: SubLangSlovenianSlovenia,
		},
		LangSomali: {
			0x1: SubLangSomaliSomalia,
		},
		LangSotho: {
			0x1: SubLangSothoSouthAfrica,
		},
		LangSpanish: {
			0xb:  SubLangSpanishArgentina,
			0x8:  SubLangSpanishBolivarianRepublicOfVenezuela,
			0x10: SubLangSpanishBolivia,
			0xd:  SubLangSpanishChile,
			0x9:  SubLangSpanishColombia,
			0x5:  SubLangSpanishCostaRica,
			0x17: SubLangSpanishCuba,
			0x7:  SubLangSpanishDominicanRepublic,
			0xc:  SubLangSpanishEcuador,
			0x11: SubLangSpanishElSalvador,
			0x4:  SubLangSpanishGuatemala,
			0x12: SubLangSpanishHonduras,
			0x16: SubLangSpanishLatinAmerica,
			0x2:  SubLangSpanishMexico,
			0x13: SubLangSpanishNicaragua,
			0x6:  SubLangSpanishPanama,
			0xf:  SubLangSpanishParaguay,
			0xa:  SubLangSpanishPeru,
			0x14: SubLangSpanishPuertoRico,
			0x1:  SubLangSpanishSpain,
			0x3:  SubLangSpanishSpain,
			0x15: SubLangSpanishUnitedStates,
			0xe:  SubLangSpanishUruguay,
		},
		LangSwedish: {
			0x2: SubLangSwedishFinland,
			0x1: SubLangSwedishSweden,
		},
		LangSyriac: {
			0x1: SubLangSyriacSyria,
		},
		LangTajikCyrillic: {
			0x1f: SubLangTajikCyrillic,
			0x1:  SubLangTajikCyrillicTajikistan,
		},
		LangTamazightLatin: {
			0x1f: SubLangTamazightLatin,
			0x2:  SubLangTamazightLatinAlgeria,
		},
		LangTamil: {
			0x1: SubLangTamilIndia,
			0x2: SubLangTamilSriLanka,
		},
		LangTatar: {
			0x1: SubLangTatarRussia,
		},
		LangTelugu: {
			0x1: SubLangTeluguIndia,
		},
		LangThai: {
			0x1: SubLangThaiThailand,
		},
		LangTibetan: {
			0x1: SubLangTibetanPeoplesRepublicOfChina,
		},
		LangTigrinya: {
			0x2: SubLangTigrinyaEritrea,
			0x1: SubLangTigrinyaEthiopia,
		},
		LangTsonga: {
			0x1: SubLangTsongaSouthAfrica,
		},
		LangTurkish: {
			0x1: SubLangTurkishTurkey,
		},
		LangTurkmen: {
			0x1: SubLangTurkmenTurkmenistan,
		},
		LangUkrainian: {
			0x1: SubLangUkrainianUkraine,
		},
		LangUpperSorbian: {
			0x1: SubLangUpperSorbianGermany,
		},
		LangUrdu: {
			0x2: SubLangUrduIndia,
			0x1: SubLangUrduIslamicRepublicOfPakistan,
		},
		LangUyghur: {
			0x1:  SubLangUyghurPeoplesRepublicOfChina,
			0x1e: SubLangUzbekCyrillic,
			0x2:  SubLangUzbekCyrillicUzbekistan,
		},
		LangUzbekLatin: {
			0x1f: SubLangUzbekLatin,
			0x1:  SubLangUzbekLatinUzbekistan,
			0x2:  SubLangValencianSpain,
		},
		LangVenda: {
			0x1: SubLangVendaSouthAfrica,
		},
		LangVietnamese: {
			0x1: SubLangVietnameseVietnam,
		},
		LangWelsh: {
			0x1: SubLangWelshUnitedKingdom,
		},
		LangWolof: {
			0x1: SubLangWolofSenegal,
		},
		LangXhosa: {
			0x1: SubLangXhosaSouthAfrica,
		},
		LangYi: {
			0x1: SubLangYiPeoplesRepublicOfChina,
			0x1: SubLangYiddishWorld,
		},
		LangYoruba: {
			0x1: SubLangYorubaNigeria,
		},
		LangZulu: {
			0x1: SubLangZuluSouthAfrica,
		},
	}
	return m[lang][subLang].String()
}

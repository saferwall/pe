# Text file containing languages and sub-languages extracted from:
# Language Identifier Constants and Strings for Microsoft Windows doc.
spec = "ms-lcid.txt"

class Language:
    language = ""
    originalLanguage = ""
    id = 0
    tag = ""
    isSubLang = False

    def __str__(self) -> str:
        return f"{self.originalLanguage} : {self.id} : {self.tag}"

def sanitize_lang(language):
    language = language.replace(".", "") # example: U.A.E.
    language = language.replace("(", "") # example: (Latin)
    language = language.replace(")", "") # example: (Latin)
    language = language.replace("'", "") # example: People's Republic of China
    language = language.replace("[", "") # example: Cocos [Keeling] Islands
    language = language.replace("]", "") # example: Cocos [Keeling] Islands
    language = language.replace("-", "") # example: Guinea-Bissau
    language = language.replace("/", "") # example: # Pseudo locale for east Asian/complex script localization testing
    language = language.replace(" ", "") # example: Congo, DRC
    language = language.replace(",", "") # example: Congo, DRC
    return language

def read_lang_ids(filename):
    lines = []
    with open(filename, 'r', encoding="utf-8") as f:
        lines = f.readlines()

    lang_ids = []
    for line in lines:
        elements = line.split()
        lang_ids.append(elements[0])

    return lang_ids

def parse_txt_file(filename, lang_ids):
    lines = []
    with open(filename, 'r', encoding="utf-8") as f:
        lines = f.readlines()

    languages = []
    for line in lines:
        lang  = Language()
        line = line.strip()
        elements = line.split()
        lang.tag = elements[-1]
        lang.id = elements[-2]
        if "-" not in lang.tag:
            lang.isSubLang = False
        else:
            if not lang.id in lang_ids:
                lang.isSubLang = True
        i = 0

        while i < len(elements) - 2:
            for letter in ["(", "["]:
                if elements[i].startswith(letter):
                    # Capitalize words so golang is happy.
                    lang.originalLanguage += letter + elements[i][1:].capitalize() + " "
                    break
                else:
                    lang.originalLanguage += elements[i].capitalize() + " "
                    break
            i += 1

        begin = lang.originalLanguage.find("-")
        if begin > 0:
            lang.originalLanguage = lang.originalLanguage[:begin+1] + \
                lang.originalLanguage[begin+1:begin+3].capitalize() + lang.originalLanguage[begin+3:]

        # Strip the last whitespace.
        lang.originalLanguage =  lang.originalLanguage[:-1]
        lang.language = sanitize_lang(lang.originalLanguage)

        # Skip unsupported locals.
        if lang.id == "0x1000":
            print (f"skipping {lang}")
            continue

        languages.append(lang)

    return languages

def generate_go_code(languages : list[Language]):
    code = ""

    # Generate langs constants
    for lang in languages:
        if lang.isSubLang:
           continue
        else:
            code += f"// {lang.originalLanguage} ({lang.tag})\n"
            code += f"Lang{lang.language} ResourceLang = {lang.id}\n"

    # Generate sub-langs constants
    i = 0
    for lang in languages:
        if lang.isSubLang:
            code += f"// {lang.originalLanguage} ({lang.tag})\n"
            code += f"SubLang{lang.language}\n"
            i += 1
    return code

def generate_lang_string(languages : list[Language]):
    code = ""
    for lang in languages:
        if lang.isSubLang:
            continue
        code += f'Lang{lang.language} :  "{lang.originalLanguage} ({lang.tag})",\n'
    return code

def generate_sub_lang_string(languages : list[Language]):
    code = ""
    for lang in languages:
        if not lang.isSubLang:
            continue
        code += f'SubLang{lang.language} :  "{lang.originalLanguage} ({lang.tag})",\n'
    return code

def generate_lang_sub_lang_map_string(languages : list[Language]):
    code = ""
    curly_bracket_is_open = False
    # The following tags don't have a location.
    ignore_list = ["0x0476", "0x05FE", "0x0501", "0x09FF", "0x043D", "0x0471", "0x045F", "0x7C67"]
    for lang in languages:
        if lang.id in ignore_list:
            continue
        if not lang.isSubLang:
            if curly_bracket_is_open:
                code += f"}},\n"
            code += f"Lang{lang.language} : {{\n"
            curly_bracket_is_open = True
        else:
            id = int(lang.id, 0) >> 10
            code += f' 0x{id:x} : SubLang{lang.language}.String(),\n'
    return code

def write_generated_code(code, filename):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(code)


if __name__ == "__main__":
    lang_ids = read_lang_ids("lang_ids.txt")
    languages = parse_txt_file(spec, lang_ids)

    code = generate_go_code(languages)
    write_generated_code(code, "out.txt")

    code = generate_lang_string(languages)
    langs = write_generated_code(code, "langs.txt")

    code = generate_sub_lang_string(languages)
    langs = write_generated_code(code, "sub_langs.txt")

    code = generate_lang_sub_lang_map_string(languages)
    langs = write_generated_code(code, "map.txt")


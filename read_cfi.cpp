#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include "dwarf.h"
#include "dwarf_string.h"

#define ElfW(what) Elf64_## what

#define CHECK(expr) \
  if (!(expr)) \
    abort()

static int64_t ReadLEB128(const char*& p) {
  int64_t result = 0;
  int64_t tmp;
  int shift = 0;
  while (*p & 0x80) {
    tmp = *p & 0x7f;
    result |= tmp << shift;
    shift += 7;
    p++;
  }
  tmp = *p;
  result |= tmp << shift;
  if (*p & 0x40) {
    result |= - ((tmp & 0x40) << shift);
  }
  p++;
  return result;
}

static uint64_t ReadULEB128(const char*& p) {
  uint64_t result = 0;
  uint64_t tmp;
  int shift = 0;
  while (*p & 0x80) {
    tmp = *p & 0x7f;
    result |= tmp << shift;
    shift += 7;
    p++;
  }
  tmp = *p;
  result |= tmp << shift;
  p++;
  return result;
}

struct DebugAbbrevAttr {
  uint64_t name;
  uint64_t form;

  DebugAbbrevAttr(uint64_t name, uint64_t form) : name(name), form(form) {
  }
};

struct DebugAbbrevDecl {
  uint64_t tag;
  bool has_child;
  std::vector<DebugAbbrevAttr> attrs;
};

struct DebugAbbrevTable {
  std::unordered_map<uint64_t, DebugAbbrevDecl> table;

  DebugAbbrevDecl* FindDecl(uint64_t abbrev_code) {
    auto it = table.find(abbrev_code);
    if (it != table.end()) {
      return &it->second;
    }
    fprintf(stderr, "can't find debug abbrev decl for code %" PRIx64 "\n",
            abbrev_code);
    return nullptr;
  }
};

class ElfReader {
 public:
  static const int LOG_HEADER = 1;
  static const int LOG_SECTION_HEADERS = 2;
  static const int LOG_DEBUG_ABBREV_SECTION = 4;

  ElfReader(const char* filename, int log_flags) : filename_(filename),
      log_flags_(log_flags), fp_(nullptr), fd_(-1) {
  }

  ~ElfReader() {
    if (fp_ != nullptr) {
      fclose(fp_);
    }
  }

  bool Open() {
    FILE* fp_ = fopen(filename_.c_str(), "rb");
    if (fp_ == nullptr) {
      fprintf(stderr, "failed to open %s\n", filename_.c_str());
      return false;
    }
    fd_ = fileno(fp_);
    if (!ReadHeader()) {
      return false;
    }
    if (!ReadSections()) {
      return false;
    }
    return true;
  }

  const ElfW(Shdr)* GetSection(const char* name) {
    auto it = sections_.find(name);
    if (it != sections_.end()) {
      return &it->second;
    }
    fprintf(stderr, "No %s section in %s\n", name, filename_.c_str());
    return nullptr;
  }

  std::vector<char> ReadSection(const ElfW(Shdr)* section) {
    std::vector<char> data(section->sh_size);
    if (!ReadFully(data.data(), data.size(), section->sh_offset)) {
      return std::vector<char>();
    }
    return data;
  }

  bool ReadDebugAbbrevSection() {
    const ElfW(Shdr)* debug_abbrev_sec = GetSection(".debug_abbrev");
    if (debug_abbrev_sec == nullptr) {
      return false;
    }
    std::vector<char> debug_abbrev_data = ReadSection(debug_abbrev_sec);
    const char* begin = debug_abbrev_data.data();
    const char* end = begin + debug_abbrev_data.size();
    const char* p = begin;
    DebugAbbrevTable* table = nullptr;
    while (p < end) {
      const char* pp = p;
      uint64_t code = ReadULEB128(p);
      if (code == 0) {
        table = nullptr;
        continue;
      }
      if (table == nullptr) {
        table = &debug_abbrev_[pp - begin];
      }
      DebugAbbrevDecl& decl = table->table[code];
      decl.tag = ReadULEB128(p);
      decl.has_child = (*p++ == DW_CHILDREN_yes);
      while (true) {
        uint64_t name = ReadULEB128(p);
        uint64_t form = ReadULEB128(p);
        if (name == 0 && form == 0) {
          break;
        }
        decl.attrs.emplace_back(name, form);
      }
    }

    if (log_flags_ & LOG_DEBUG_ABBREV_SECTION) {
      printf(".debug_abbrev section:\n");
      p = begin;
      while (p < end) {
        const char* pp = p;
        uint64_t code = ReadULEB128(p);
        printf("<%lx> code %" PRIx64 "\n", pp - begin, code);
        if (code == 0) {
          continue;
        }
        pp = p;
        uint64_t tag = ReadULEB128(p);
        const char* tag_str = "";
        auto it = DWARF_TAG_MAP.find(tag);
        if (it != DWARF_TAG_MAP.end()) {
          tag_str = it->second;
        }
        printf("<%lx> tag %s(%" PRIx64 ")\n", pp - begin, tag_str, tag);
        pp = p;
        int8_t has_child = *p++;
        printf("<%lx> has_child %d (%s)\n", pp - begin, has_child,
               (has_child == DW_CHILDREN_no ? "no" : "yes"));
        while (true) {
          pp = p;
          uint64_t name = ReadULEB128(p);
          const char* name_str = "";
          auto it = DWARF_AT_MAP.find(name);
          if (it != DWARF_AT_MAP.end()) {
            name_str = it->second;
          }
          uint64_t form = ReadULEB128(p);
          const char* form_str = "";
          it = DWARF_FORM_MAP.find(form);
          if (it != DWARF_FORM_MAP.end()) {
            form_str = it->second;
          }
          printf("<%lx> attr name %s(%" PRIx64 "), form %s(%" PRIx64 ")\n", pp - begin,
                 name_str, name, form_str, form);
          if (name == 0 && form == 0) {
            break;
          }
        }
      }
    }
    return true;
  }

  DebugAbbrevTable* GetDebugAbbrevTable(uint64_t offset_in_debug_abbrev_section) {
    auto it = debug_abbrev_.find(offset_in_debug_abbrev_section);
    if (it != debug_abbrev_.end()) {
      return &it->second;
    }
    fprintf(stderr, "can't find debug abbrev table at offset %" PRIx64 "\n",
            offset_in_debug_abbrev_section);
    return nullptr;
  }

 private:
  bool ReadHeader() {
    if (!ReadFully(&header_, sizeof(header_), 0)) {
      return false;
    }
    if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
      fprintf(stderr, "elf magic doesn't match\n");
      return false;
    }
    int elf_class = header_.e_ident[EI_CLASS];
    if (elf_class != ELFCLASS64) {
      fprintf(stderr, "elf format is 32-bit\n");
      return false;
    }
    if (log_flags_ & LOG_HEADER) {
      printf("section offset: %lx\n", (unsigned long)header_.e_shoff);
      printf("section num: %lx\n", (unsigned long)header_.e_shnum);
      printf("section entry size: %lx\n", (unsigned long)header_.e_shentsize);
      printf("string section index: %lu\n", (unsigned long)header_.e_shstrndx);
    }
    return true;
  }

  bool ReadSections() {
    CHECK(header_.e_shstrndx != 0);
    ElfW(Shdr) str_sec;
    if (!ReadFully(&str_sec, sizeof(str_sec), header_.e_shoff + header_.e_shstrndx *
                   header_.e_shentsize)) {
      return false;
    }
    string_section_.resize(str_sec.sh_size);
    if (!ReadFully(string_section_.data(), str_sec.sh_size, str_sec.sh_offset)) {
      return false;
    }
    unsigned long offset = header_.e_shoff;
    for (int i = 0; i < header_.e_shnum; ++i, offset += header_.e_shentsize) {
      ElfW(Shdr) sec;
      if (!ReadFully(&sec, sizeof(sec), offset)) {
        return false;
      }
      const char* name = &string_section_[sec.sh_name];
      if (name[0] == '\0') {
        continue;
      }
      sections_[name] = sec;
    }
    if (log_flags_ & LOG_SECTION_HEADERS) {
      for (auto& pair : sections_) {
        printf("section %s, addr %lx, offset %lx, size %lx\n",
               pair.first.c_str(), (unsigned long)pair.second.sh_addr,
               (unsigned long)pair.second.sh_offset,
               (unsigned long)pair.second.sh_size);
      }
    }
    return true;
  }


  bool ReadFully(void* buf, size_t size, size_t offset) {
    ssize_t rc = TEMP_FAILURE_RETRY(pread64(fd_, buf, size, offset));
    if (rc < 0) {
      fprintf(stderr, "failed to read file: %s\n", strerror(errno));
      return false;
    }
    if (rc != size) {
      fprintf(stderr, "not read fully\n");
      return false;
    }
    return true;
  }

  const std::string filename_;
  int log_flags_;
  FILE* fp_;
  int fd_;
  ElfW(Ehdr) header_;
  std::map<std::string, ElfW(Shdr)> sections_;
  std::vector<char> string_section_;
  std::map<uint64_t, DebugAbbrevTable> debug_abbrev_;
};

/*
bool readEhFrameHdr(FILE* fp, ElfW(Shdr)* section) {
  char data[section->sh_size];
  if (!ReadFully(fp, data, section->sh_size, section->sh_offset)) {
    return false;
  }
  printf("eh_frame_hdr: addr %lx offset %lx, size %lx\n",
         (unsigned long)section->sh_addr, (unsigned long)section->sh_offset,
         (unsigned long)section->sh_size);
  printf(" version: %d\n", data[0]);
  printf(" eh_frame_ptr_enc: %x\n", data[1]);
  printf(" fde_count_enc: %x\n", data[2]);
  printf(" table_enc: %x\n", data[3]);
  char eh_frame_ptr_enc = data[1];
  if ((eh_frame_ptr_enc & 0x0f) != 0x0b) {
    return false;
  }
  int32_t eh_frame_ptr = *(int32_t*)(&data[4]);
  printf("eh_frame_ptr = %x\n", eh_frame_ptr);
  char fde_count_enc = data[2];
  if ((fde_count_enc & 0x0f) != 0x03) {
    return false;
  }
  uint32_t fde_count = *(uint32_t*)(&data[8]);
  printf("fde_count = %u\n", fde_count);
  char table_enc = data[3];
  if (table_enc != 0x3b) {
    return false;
  }
  int32_t* p = (int32_t*)&data[12];
  for (int i = 0; i < fde_count; ++i) {
    int32_t loc = *p++;
    int32_t addr = *p++;
    printf("table[%d], loc %x, addr %x\n", i, loc, addr);
  }
  return true;
}
*/

/*
bool ReadDebugAbbrevSection(ElfReader& reader) {
  const ElfW(Shdr)* debug_abbrev_sec = reader.GetSection(".debug_abbrev");
  if (debug_abbrev_sec == nullptr) {
    return false;
  }
  std::vector<char> debug_abbrev_data = reader.ReadSection(debug_abbrev_sec);
  const char* begin = debug_abbrev_data.data();
  const char* end = begin + debug_abbrev_data.size();
  const char* p = begin;
  printf(".debug_abbrev section:\n");
  while (p < end) {
    const char* pp = p;
    uint64_t code = ReadULEB128(p);
    printf("<%lx> code %" PRIx64 "\n", pp - begin, code);
    if (code == 0) {
      continue;
    }
    pp = p;
    uint64_t tag = ReadULEB128(p);
    const char* tag_str = "";
    auto it = DWARF_TAG_MAP.find(tag);
    if (it != DWARF_TAG_MAP.end()) {
      tag_str = it->second;
    }
    printf("<%lx> tag %s(%" PRIx64 ")\n", pp - begin, tag_str, tag);
    pp = p;
    int8_t has_child = *p++;
    printf("<%lx> has_child %d (%s)\n", pp - begin, has_child,
           (has_child == DW_CHILDREN_no ? "no" : "yes"));
    while (true) {
      pp = p;
      uint64_t name = ReadULEB128(p);
      const char* name_str = "";
      auto it = DWARF_AT_MAP.find(name);
      if (it != DWARF_AT_MAP.end()) {
        name_str = it->second;
      }
      uint64_t form = ReadULEB128(p);
      const char* form_str = "";
      it = DWARF_FORM_MAP.find(form);
      if (it != DWARF_FORM_MAP.end()) {
        form_str = it->second;
      }
      printf("<%lx> attr name %s(%" PRIx64 "), form %s(%" PRIx64 ")\n", pp - begin,
             name_str, name, form_str, form);
      if (name == 0 && form == 0) {
        break;
      }
    }
  }
  return true;
}
*/

bool ReadElf(const char* filename) {
  int log_flag = ElfReader::LOG_HEADER | ElfReader::LOG_SECTION_HEADERS | ElfReader::LOG_DEBUG_ABBREV_SECTION;
  ElfReader reader(filename, log_flag);
  if (!reader.Open()) {
    return false;
  }
  if (!reader.ReadDebugAbbrevSection()) {
    return false;
  }
  const ElfW(Shdr)* debug_info_sec = reader.GetSection(".debug_info");
  if (debug_info_sec == nullptr) {
    return false;
  }
  std::vector<char> debug_info_data = reader.ReadSection(debug_info_sec);
  printf(".debug_info section size %zu\n", debug_info_data.size());
  const char* begin = debug_info_data.data();
  const char* p = debug_info_data.data();
  const char* end = p + debug_info_data.size();
  while (p < end) {
    bool section64 = false;
    uint64_t unit_len = 0;
    uint32_t len = *(const uint32_t*)p;
    p += 4;
    if (len == 0xffffffff) {
      section64 = true;
      unit_len = *(const uint64_t*)p;
      p += 8;
    } else {
      unit_len = len;
    }
    const char* cend = p + len;
    uint16_t version = *reinterpret_cast<const uint16_t*>(p);
    p += 2;
    uint64_t debug_abbrev_offset = 0;
    if (section64) {
      debug_abbrev_offset = *(const uint64_t*)p;
      p += 8;
    } else {
      debug_abbrev_offset = *(const uint32_t*)p;
      p += 4;
    }
    uint8_t address_size = *(const uint8_t*)p;
    p++;
    printf("compile unit header(%u)\n", section64 ? 64 : 32);
    printf("\tunit_len %" PRIx64 ", version %u\n", unit_len, version);
    printf("\tdebug_abbrev_offset %" PRIx64 ", address_size %u\n", debug_abbrev_offset,
           address_size);
    DebugAbbrevTable* abbrev_table = reader.GetDebugAbbrevTable(debug_abbrev_offset);
    if (abbrev_table == nullptr) {
      return false;
    }
    while (p < cend) {
      const char* pp = p;
      uint64_t abbrev_code = ReadULEB128(p);
      printf("<%lx>abrev_code: %" PRIx64 "\n", pp - begin, abbrev_code);
      DebugAbbrevDecl* abbrev_decl = abbrev_table->FindDecl(abbrev_code);
      if (abbrev_decl == nullptr) {
        return false;
      }

      p = cend;

    }
  }
  return true;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "no filename\n");
    exit(1);
  }
  const char* filename = argv[1];
  ReadElf(filename);
  return 0;
}

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

#define DEBUG_CFI

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

static uint64_t Read(const char*& p, int size) {
  const char* q = p;
  p += size;
  switch (size) {
    case 1: return *(const uint8_t*)q;
    case 2: return *(const uint16_t*)q;
    case 4: return *(const uint32_t*)q;
    case 8: return *(const uint64_t*)q;
  }
  fprintf(stderr, "Read size = %d\n", size);
  abort();
}

static int64_t ReadS(const char*& p, int size) {
  const char* q = p;
  p += size;
  switch (size) {
    case 1: return *(const int8_t*)q;
    case 2: return *(const int16_t*)q;
    case 4: return *(const int32_t*)q;
    case 8: return *(const int64_t*)q;
  }
  fprintf(stderr, "ReadS size = %d\n", size);
  abort();
}

static const char* ReadStr(const char*& p) {
  const char* result = p;
  p += strlen(p) + 1;
  return result;
}

static uint64_t ReadEhEncoding(const char*& p, uint8_t encoding) {
  encoding &= 0x0f;
  switch (encoding) {
    case DW_EH_PE_omit:
      return 0;
    case DW_EH_PE_uleb128:
      return ReadULEB128(p);
    case DW_EH_PE_udata2:
      return Read(p, 2);
    case DW_EH_PE_udata4:
      return Read(p, 4);
    case DW_EH_PE_udata8:
      return Read(p, 8);
    case DW_EH_PE_sleb128:
      return ReadLEB128(p);
    case DW_EH_PE_sdata2:
      return ReadS(p, 2);
    case DW_EH_PE_sdata4:
      return ReadS(p, 4);
    case DW_EH_PE_sdata8:
      return ReadS(p, 8);
  }
  fprintf(stderr, "ReadEhEncoding: unsupported 0x%x\n", encoding);
  abort();
}

static void PrintHex(const char* p, uint64_t len) {
  for (uint64_t i = 0; i < len; ++i) {
    printf("%x ", (unsigned char)p[i]);
  }
  printf("\n");
}

static const char* FindMap(const std::unordered_map<int, const char*>& map, uint64_t key) {
  auto it = map.find(key);
  if (it != map.end()) {
    return it->second;
  }
  return "";
}

static const char* FindCFAInst(uint8_t inst) {
  if (inst & 0xc0) {
    inst &= 0xc0;
  }
  return FindMap(DWARF_CFA_INST_MAP, inst);
}

struct DebugAbbrevAttr {
  uint64_t name;
  uint64_t form;
#if defined(DEBUG_CFI)
  const char* name_str;
  const char* form_str;
#endif

  DebugAbbrevAttr(uint64_t name, uint64_t form) : name(name), form(form) {
  }
};

struct DebugAbbrevDecl {
  uint64_t tag;
  bool has_child;
  std::vector<DebugAbbrevAttr> attrs;
#if defined(DEBUG_CFI)
  const char* tag_str;
#endif
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

struct Cie {
  uint8_t fde_pointer_encoding;
  uint8_t lsda_encoding;
  int address_size;
  const char* augmentation;
  uint64_t data_alignment_factor;
};

struct CieTable {
  // From offset in .debug_frame or .eh_frame to CIE.
  std::unordered_map<uint64_t, Cie> table;

  Cie* CreateCie(uint64_t offset) {
    Cie* cie = &table[offset];
    cie->fde_pointer_encoding = 0;
    cie->lsda_encoding = 0;
    cie->address_size = 0;
    cie->augmentation = nullptr;
    cie->data_alignment_factor = 0;
    return cie;
  }

  Cie* FindCie(uint64_t offset) {
    auto it = table.find(offset);
    if (it != table.end()) {
      return &it->second;
    }
    fprintf(stderr, "can't find cie at offset 0x%" PRIx64 "\n", offset);
    return nullptr;
  }
};

class ElfReader {
 private:
  static const int READ_DEBUG_ABBREV_SECTION = 1;
  static const int READ_DEBUG_STR_SECTION = 2;
  static const int READ_DEBUG_INFO_SECTION = 4;
  static const int READ_EH_FRAME_SECTION = 8;

 public:
  static const int LOG_HEADER = 1;
  static const int LOG_SECTION_HEADERS = 2;
  static const int LOG_DEBUG_ABBREV_SECTION = 4;

  ElfReader(const char* filename, int log_flags) : filename_(filename),
      log_flags_(log_flags), read_section_flag_(0), fp_(nullptr), fd_(-1) {
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
    if (read_section_flag_ & READ_DEBUG_ABBREV_SECTION) {
      return true;
    }
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
#if defined(DEBUG_CFI)
      decl.tag_str = FindMap(DWARF_TAG_MAP, decl.tag);
#endif
      decl.has_child = (*p++ == DW_CHILDREN_yes);
      while (true) {
        uint64_t name = ReadULEB128(p);
        uint64_t form = ReadULEB128(p);
        if (name == 0 && form == 0) {
          break;
        }
        decl.attrs.emplace_back(name, form);
#if defined(DEBUG_CFI)
        decl.attrs.back().name_str = FindMap(DWARF_AT_MAP, name);
        decl.attrs.back().form_str = FindMap(DWARF_FORM_MAP, form);
#endif
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
        const char* tag_str = FindMap(DWARF_TAG_MAP, tag);
        printf("<%lx> tag %s(%" PRIx64 ")\n", pp - begin, tag_str, tag);
        pp = p;
        int8_t has_child = *p++;
        printf("<%lx> has_child %d (%s)\n", pp - begin, has_child,
               (has_child == DW_CHILDREN_no ? "no" : "yes"));
        while (true) {
          pp = p;
          uint64_t name = ReadULEB128(p);
          const char* name_str = FindMap(DWARF_AT_MAP, name);
          uint64_t form = ReadULEB128(p);
          const char* form_str = FindMap(DWARF_FORM_MAP, form);
          printf("<%lx> attr name %s(%" PRIx64 "), form %s(%" PRIx64 ")\n", pp - begin,
                 name_str, name, form_str, form);
          if (name == 0 && form == 0) {
            break;
          }
        }
      }
    }
    read_section_flag_ |= READ_DEBUG_ABBREV_SECTION;
    return true;
  }

  DebugAbbrevTable* GetDebugAbbrevTable(uint64_t offset_in_debug_abbrev_section) {
    CHECK(read_section_flag_ & READ_DEBUG_ABBREV_SECTION);
    auto it = debug_abbrev_.find(offset_in_debug_abbrev_section);
    if (it != debug_abbrev_.end()) {
      return &it->second;
    }
    fprintf(stderr, "can't find debug abbrev table at offset %" PRIx64 "\n",
            offset_in_debug_abbrev_section);
    return nullptr;
  }

  bool ReadDebugStrSection() {
    if (read_section_flag_ & READ_DEBUG_STR_SECTION) {
      return true;
    }
    const ElfW(Shdr)* debug_str_sec = GetSection(".debug_str");
    if (debug_str_sec == nullptr) {
      return false;
    }
    debug_str_data_ = ReadSection(debug_str_sec);
    read_section_flag_ |= READ_DEBUG_STR_SECTION;
    return true;
  }

  const char* GetDebugStr() {
    CHECK(read_section_flag_ & READ_DEBUG_STR_SECTION);
    return debug_str_data_.data();
  }

  bool ReadDebugInfoSection() {
    if (read_section_flag_ & READ_DEBUG_INFO_SECTION) {
      return true;
    }
    if (!ReadDebugAbbrevSection()) {
      return false;
    }
    if (!ReadDebugStrSection()) {
      return false;
    }
    const char* debug_str = GetDebugStr();
    const ElfW(Shdr)* debug_info_sec = GetSection(".debug_info");
    if (debug_info_sec == nullptr) {
      return false;
    }
    std::vector<char> debug_info_data = ReadSection(debug_info_sec);
    printf(".debug_info section size %zu\n", debug_info_data.size());
    const char* begin = debug_info_data.data();
    const char* p = debug_info_data.data();
    const char* end = p + debug_info_data.size();
    while (p < end) {
      bool section64 = false;
      int secbytes = 4;
      uint64_t unit_len = 0;
      uint32_t len = Read(p, 4);
      if (len == 0xffffffff) {
        section64 = true;
        secbytes = 8;
        unit_len = Read(p, 8);
      } else {
        unit_len = len;
      }
      const char* cend = p + len;
      uint16_t version = Read(p, 2);
      uint64_t debug_abbrev_offset = Read(p, secbytes);
      uint8_t address_size = Read(p, 1);
      printf("compile unit header(%u)\n", section64 ? 64 : 32);
      printf("\tunit_len %" PRIx64 ", version %u\n", unit_len, version);
      printf("\tdebug_abbrev_offset %" PRIx64 ", address_size %u\n", debug_abbrev_offset,
             address_size);
      DebugAbbrevTable* abbrev_table = GetDebugAbbrevTable(debug_abbrev_offset);
      if (abbrev_table == nullptr) {
        return false;
      }
      while (p < cend) {
        const char* pp = p;
        uint64_t abbrev_code = ReadULEB128(p);
        if (abbrev_code == 0) {
          printf("<%lx>abbrev_code: 0\n", pp - begin);
          continue;
        }
        DebugAbbrevDecl* abbrev_decl = abbrev_table->FindDecl(abbrev_code);
        if (abbrev_decl == nullptr) {
          printf("<%lx>abrev_code: %" PRIx64 "\n", pp - begin, abbrev_code);
          return false;
        }
        printf("<%lx>abrev_code: %" PRIx64 " (%s)\n", pp - begin, abbrev_code, abbrev_decl->tag_str);
        for (auto& attr : abbrev_decl->attrs) {
          printf("<%lx> %s : %s : ", p - begin, attr.name_str, attr.form_str);
          uint64_t form = attr.form;
          uint64_t data = 0;
          switch (form) {
            case DW_FORM_strp: {
              uint64_t offset = Read(p, secbytes);
              const char* s = debug_str + offset;
              printf("%s\n", s);
              break;
            }
            case DW_FORM_string: {
              const char* s = p;
              p += strlen(s) + 1;
              printf("%s\n", s);
              break;
            }
            case DW_FORM_data1:
            case DW_FORM_data2:
            case DW_FORM_data4:
            case DW_FORM_data8: {
              if (form == DW_FORM_data1) {
                data = Read(p, 1);
              } else if (form == DW_FORM_data2) {
                data = Read(p, 2);
              } else if (form == DW_FORM_data4) {
                data = Read(p, 4);
              } else {
                data = Read(p, 8);
              }
              printf("%" PRIx64 "\n", data);
              break;
            }
            case DW_FORM_sec_offset: {
              data = Read(p, secbytes);
              printf("%" PRIx64 "\n", data);
              break;
            }
            case DW_FORM_addr: {
              data = Read(p, address_size);
              printf("%" PRIx64 "\n", data);
              break;
            }
            case DW_FORM_ref1:
            case DW_FORM_ref2:
            case DW_FORM_ref4:
            case DW_FORM_ref8: {
              if (form == DW_FORM_ref1) {
                data = Read(p, 1);
              } else if (form == DW_FORM_ref2) {
                data = Read(p, 2);
              } else if (form == DW_FORM_ref4) {
                data = Read(p, 4);
              } else {
                data = Read(p, 8);
              }
              printf("%" PRIx64 "\n", data);
              break;
            }
            case DW_FORM_flag:
            case DW_FORM_flag_present: {
              bool flag = true;
              if (form == DW_FORM_flag) {
                flag = (Read(p, 1) == 1);
              }
              printf("%s\n", flag ? "true" : "false");
              break;
            }
            case DW_FORM_exprloc: {
              uint64_t len = ReadULEB128(p);
              printf("len %" PRIx64 ": ", len);
              PrintHex(p, len);
              p += len;
              break;
            }
            default: {
              fprintf(stderr, "unexpected attr.form\n");
              abort();
              break;
            }
          }
          switch (attr.name) {
            case DW_AT_language: {
              const char* s = FindMap(DWARF_LANGUAGE_MAP, data);
              printf("\tlanguage: %s\n", s);
              break;
            }
          }
        }
      }
    }
    read_section_flag_ |= READ_DEBUG_INFO_SECTION;
    return true;
  }

  bool ReadEhFrameSection() {
    if (read_section_flag_ & READ_EH_FRAME_SECTION) {
      return true;
    }
    const ElfW(Shdr)* eh_frame_sec = GetSection(".eh_frame");
    if (eh_frame_sec == nullptr) {
      return false;
    }
    std::vector<char> eh_frame_data = ReadSection(eh_frame_sec);
    const char* begin = eh_frame_data.data();
    const char* end = begin + eh_frame_data.size();
    const char* p = begin;
    bool is_eh_frame = true;
    printf(".eh_frame:\n");
    CieTable cie_table;
    while (p < end) {
      const char* cie_begin = p;
      bool section64 = false;
      int secbytes = 4;
      uint64_t unit_len = 0;
      uint32_t len = Read(p, 4);
      if (len == 0xffffffff) {
        section64 = true;
        secbytes = 8;
        unit_len = Read(p, 8);
      } else {
        unit_len = len;
      }
      if (unit_len == 0) {
        printf("<%lx> zero terminator\n", cie_begin - begin);
        continue;
      }
      const char* cie_end = p + unit_len;
      uint64_t cie_id = Read(p, secbytes);
      if (!section64 && cie_id == DW_CIE_ID_32) {
        cie_id = DW_CIE_ID_64;
      }
      bool is_cie = (is_eh_frame ? cie_id == 0 : cie_id == DW_CIE_ID_64);
      printf("\n<%lx> cie_id %" PRIx64 " %s\n", cie_begin - begin, cie_id, is_cie ? "CIE" : "FDE");
      Cie* cie = nullptr;
      uint64_t current_loc = 0;
      if (is_cie) {
        cie = cie_table.CreateCie(cie_begin - begin);
        uint8_t version = Read(p, 1);
        printf("version %u\n", version);
        const char* augmentation = ReadStr(p);
        cie->augmentation = augmentation;
        printf("augmentation %s\n", augmentation);
        CHECK(augmentation[0] == '\0' || augmentation[0] == 'z');
        uint8_t address_size = 8; // ELF32 or ELF64
        if (version >= 4) {
          address_size = Read(p, 1);
          uint8_t segment_size = Read(p, 1);
          printf("address_size %d, segment_size %d\n", address_size, segment_size);
        }
        cie->address_size = address_size;
        uint64_t code_alignment_factor = ReadULEB128(p);
        int64_t data_alignment_factor = ReadLEB128(p);
        printf("code_alignment_factor %" PRIu64 ", data_alignment_factor %" PRId64 "\n",
               code_alignment_factor, data_alignment_factor);
        cie->data_alignment_factor = data_alignment_factor;
        uint64_t return_address_register;
        if (version == 1) {
          return_address_register = Read(p, 1);
        } else {
          return_address_register = ReadULEB128(p);
        }
        printf("return_address_register %" PRIu64 "\n", return_address_register);
        if (augmentation[0] == 'z') {
          uint64_t augmentation_len = ReadULEB128(p);
          printf("augmentation_len %" PRIu64 "\n", augmentation_len);
          for (int i = 1; augmentation[i] != '\0'; ++i) {
            char c = augmentation[i];
            if (c == 'R') {
              uint8_t fde_pointer_encoding = Read(p, 1);
              cie->fde_pointer_encoding = fde_pointer_encoding;
              printf("fde_pointer_encoding %x\n", fde_pointer_encoding);
            } else if (c == 'P') {
              uint8_t encoding = Read(p, 1);
              const char* encoding_str = FindMap(DWARF_EH_ENCODING_MAP, encoding);
              printf("personality pointer encoding 0x%x (%s)\n", encoding, encoding_str);
              uint64_t personality_handler = ReadEhEncoding(p, encoding);
              printf("personality pointer 0x%" PRIx64 "\n", personality_handler);
            } else if (c == 'L') {
              uint8_t lsda_encoding = Read(p, 1);
              cie->lsda_encoding = lsda_encoding;
              const char* encoding_str = FindMap(DWARF_EH_ENCODING_MAP, lsda_encoding);
              printf("lsda_encoding 0x%x (%s)\n", lsda_encoding, encoding_str);
            } else {
              fprintf(stderr, "unexpected augmentation %c\n", c);
              abort();
            }
          }
        }
        // initial_instructions
        printf("initial_instructions len 0x%lx\n", cie_end - p);
      } else {
        uint64_t cie_offset = (is_eh_frame ? p - secbytes - begin - cie_id : cie_id);
        printf("cie_offset 0x%" PRIx64 "\n", cie_offset);
        cie = cie_table.FindCie(cie_offset);
        if (cie == nullptr) {
          return false;
        }
        const char* base = p;
        uint64_t initial_location = ReadEhEncoding(p, cie->fde_pointer_encoding);
        uint64_t address_range = ReadEhEncoding(p, cie->fde_pointer_encoding);
        printf("initial_location 0x%" PRIx64 ", address_range 0x%" PRIx64"\n",
               initial_location, address_range);
        uint64_t proc_start = initial_location;
        if ((cie->fde_pointer_encoding & 0x70) == DW_EH_PE_pcrel) {
          proc_start += eh_frame_sec->sh_addr + (base - begin);
        }
        printf("proc range [0x%" PRIx64 " - 0x%" PRIx64 "]\n", proc_start, proc_start + address_range);
        if (cie->augmentation[0] == 'z') {
          uint64_t augmentation_len = ReadULEB128(p);
          printf("augmentation_len %" PRIu64 "\n", augmentation_len);
        }
        if (cie->lsda_encoding) {
          uint64_t lsda = ReadEhEncoding(p, cie->lsda_encoding);
          printf("lsda 0x%" PRIx64 "\n", lsda);
        }
        printf("instructions len 0x%lx\n", cie_end - p);
        current_loc = proc_start;
      }
      while (p < cie_end) {
        uint8_t inst = Read(p, 1);
        printf("inst %s (0x%x): ", FindCFAInst(inst), inst);
        if (inst & 0xc0) {
          uint8_t t = inst & 0xc0;
          if (t == DW_CFA_advance_loc) {
            uint8_t delta = inst & 0x3f;
            current_loc += delta;
            printf("loc = loc + 0x%x = 0x%" PRIx64, delta, current_loc);
          } else if (t == DW_CFA_offset) {
            uint8_t reg = inst & 0x3f;
            uint64_t offset = ReadULEB128(p);
            int64_t add = offset * cie->data_alignment_factor;
            if (add >= 0) {
              printf("r%u = mem(cfa + 0x%" PRIx64 ")", reg, add);
            } else {
              printf("r%u = mem(cfa - 0x%" PRIx64 ")", reg, -add);
            }
          } else if (t == DW_CFA_restore) {
            uint8_t reg = inst & 0x3f;
          }
        } else {
          switch (inst) {
            case DW_CFA_nop: {
              break;
            }
            case DW_CFA_set_loc: {
              uint64_t addr = Read(p, cie->address_size);
              break;
            }
            case DW_CFA_advance_loc1:
            case DW_CFA_advance_loc2:
            case DW_CFA_advance_loc4: {
              uint32_t delta;
              if (inst == DW_CFA_advance_loc1) {
                delta = Read(p, 1);
              } else if (inst == DW_CFA_advance_loc2) {
                delta = Read(p, 2);
              } else {
                delta = Read(p, 4);
              }
              current_loc += delta;
              printf("loc = loc + 0x%u = 0x%" PRIx64, delta, current_loc);
              break;
            }
            case DW_CFA_offset_extended: {
              uint64_t reg = ReadULEB128(p);
              uint64_t offset = ReadULEB128(p);
              break;
            }
            case DW_CFA_restore_extended: {
              uint64_t reg = ReadULEB128(p);
              break;
            }
            case DW_CFA_undefined: {
              uint64_t reg = ReadULEB128(p);
              printf("r%" PRIu64 " = undefined", reg);
              break;
            }
            case DW_CFA_same_value: {
              uint64_t reg = ReadULEB128(p);
              break;
            }
            case DW_CFA_register: {
              uint64_t reg1 = ReadULEB128(p);
              uint64_t reg2 = ReadULEB128(p);
              break;
            }
            case DW_CFA_remember_state: {
              break;
            }
            case DW_CFA_restore_state: {
              break;
            }
            case DW_CFA_def_cfa: {
              uint64_t reg = ReadULEB128(p);
              uint64_t offset = ReadULEB128(p);
              printf("cfa = r%" PRIu64 " + off 0x%" PRIx64, reg, offset);
              break;
            }
            case DW_CFA_def_cfa_register: {
              uint64_t reg = ReadULEB128(p);
              printf("cfa = r%" PRIu64 " + old off", reg);
              break;
            }
            case DW_CFA_def_cfa_offset: {
              uint64_t offset = ReadULEB128(p);
              printf("cfa = old_reg + off 0x%" PRIx64, offset);
              break;
            }
            case DW_CFA_def_cfa_expression: {
               uint64_t len = ReadULEB128(p);
               printf("cfa = ");
               if (!ParseDwarfExpression(p, len, section64, cie->address_size)) {
                 return false;
               }
               p += len;
               break;
            }
            case DW_CFA_expression: {
              uint64_t reg = ReadULEB128(p);
              uint64_t len = ReadULEB128(p);
              if (!ParseDwarfExpression(p, len, section64, cie->address_size)) {
                return false;
              }
              p += len;
              break;
            }
            case DW_CFA_offset_extended_sf: {
              uint64_t reg = ReadULEB128(p);
              int64_t offset = ReadLEB128(p);
              break;
            }
            case DW_CFA_def_cfa_sf: {
              uint64_t reg = ReadULEB128(p);
              int64_t offset = ReadLEB128(p);
              break;
            }
            case DW_CFA_def_cfa_offset_sf: {
              int64_t offset = ReadLEB128(p);
              break;
            }
            case DW_CFA_val_offset: {
              uint64_t reg = ReadULEB128(p);
              uint64_t offset = ReadULEB128(p);
              break;
            }
            case DW_CFA_val_offset_sf: {
              uint64_t reg = ReadULEB128(p);
              int64_t offset = ReadLEB128(p);
              break;
            }
            case DW_CFA_val_expression: {
              uint64_t reg = ReadULEB128(p);
              uint64_t len = ReadULEB128(p);
              p += len;
              break;
            }
            default: {
              fprintf(stderr, "unknown cfa inst: 0x%x\n", inst);
              abort();
            }
          }
        }
        printf("\n");
      }
    }
    read_section_flag_ |= READ_EH_FRAME_SECTION;
    return true;
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

  bool ParseDwarfExpression(const char* p, uint64_t len, bool is64, int addrsize) {
    const char* end = p + len;
    while (p < end) {
      uint8_t inst = *p++;
      printf("%s ", FindMap(DWARF_OP_MAP, inst));
      if (inst >= DW_OP_lit0 && inst <= DW_OP_lit31) {
        continue;
      } else if (inst >= DW_OP_reg0 && inst <= DW_OP_reg31) {
        continue;
      } else if (inst >= DW_OP_breg0 && inst <= DW_OP_breg31) {
        int64_t offset = ReadLEB128(p);
        continue;
      }
      switch (inst) {
        case DW_OP_addr: {
          uint64_t addr = Read(p, addrsize);
          break;
        }
        case DW_OP_deref: {
          break;
        }
        case DW_OP_const1u:
        case DW_OP_const2u:
        case DW_OP_const4u:
        case DW_OP_const8u: {
          int size;
          if (inst == DW_OP_const1u) {
            size = 1;
          } else if (inst == DW_OP_const2u) {
            size = 2;
          } else if (inst == DW_OP_const4u) {
            size = 4;
          } else if (inst == DW_OP_const8u) {
            size = 8;
          }
          uint64_t value = Read(p, size);
          break;
        }
        case DW_OP_const1s:
        case DW_OP_const2s:
        case DW_OP_const4s:
        case DW_OP_const8s: {
          int size;
          if (inst == DW_OP_const1s) {
            size = 1;
          } else if (inst == DW_OP_const2s) {
            size = 2;
          } else if (inst == DW_OP_const4s) {
            size = 4;
          } else if (inst == DW_OP_const8s) {
            size = 8;
          }
          int64_t value = ReadS(p, size);
          break;
        }
        case DW_OP_constu: {
          uint64_t value = ReadULEB128(p);
          break;
        }
        case DW_OP_consts: {
          int64_t value = ReadLEB128(p);
          break;
        }
        case DW_OP_dup:
        case DW_OP_drop:
        case DW_OP_over: {
          break;
        }
        case DW_OP_pick: {
          uint8_t index = Read(p, 1);
          break;
        }
        case DW_OP_swap:
        case DW_OP_rot:
        case DW_OP_xderef:
        case DW_OP_abs:
        case DW_OP_and:
        case DW_OP_div:
        case DW_OP_minus:
        case DW_OP_mod:
        case DW_OP_mul:
        case DW_OP_neg:
        case DW_OP_not:
        case DW_OP_or:
        case DW_OP_plus: {
          break;
        }
        case DW_OP_plus_uconst: {
          uint64_t value = ReadULEB128(p);
          break;
        }
        case DW_OP_shl:
        case DW_OP_shr:
        case DW_OP_shra:
        case DW_OP_xor: {
          break;
        }
        case DW_OP_skip:
        case DW_OP_bra: {
          int64_t value = ReadS(p, 2);
          break;
        }
        case DW_OP_eq:
        case DW_OP_ge:
        case DW_OP_gt:
        case DW_OP_le:
        case DW_OP_lt:
        case DW_OP_ne: {
          break;
        }
        case DW_OP_regx: {
          uint64_t reg = ReadULEB128(p);
          break;
        }
        case DW_OP_fbreg: {
          int64_t offset = ReadLEB128(p);
          break;
        }
        case DW_OP_bregx: {
          uint64_t reg = ReadULEB128(p);
          int64_t offset = ReadLEB128(p);
          break;
        }
        case DW_OP_piece: {
          uint64_t size = ReadULEB128(p);
          break;
        }
        case DW_OP_deref_size:
        case DW_OP_xderef_size: {
          uint8_t data = Read(p, 1);
          break;
        }
        case DW_OP_nop:
        case DW_OP_push_object_address: {
          break;
        }
        case DW_OP_call2: {
          uint16_t offset = Read(p, 2);
          break;
        }
        case DW_OP_call4: {
          uint32_t offset = Read(p, 4);
          break;
        }
        case DW_OP_call_ref: {
          uint64_t offset = Read(p, (is64 ? 8 : 4));
          break;
        }
        case DW_OP_form_tls_address:
        case DW_OP_call_frame_cfa:  {
          break;
        }
        case DW_OP_bit_piece:
        case DW_OP_implicit_value: {
          uint64_t size = ReadULEB128(p);
          uint64_t offset = ReadULEB128(p);
          break;
        }
        case DW_OP_stack_value: {
          break;
        }
        default: {
          fprintf(stderr, "unexpected dwarf expression inst: 0x%x\n", inst);
          return false;
        }
      }
    }
    return true;
  }

  const std::string filename_;
  int log_flags_;
  int read_section_flag_;
  FILE* fp_;
  int fd_;
  ElfW(Ehdr) header_;
  std::map<std::string, ElfW(Shdr)> sections_;
  std::vector<char> string_section_;
  std::map<uint64_t, DebugAbbrevTable> debug_abbrev_;
  std::vector<char> debug_str_data_;
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

bool ReadElf(const char* filename) {
  int log_flag = ElfReader::LOG_HEADER | ElfReader::LOG_SECTION_HEADERS | ElfReader::LOG_DEBUG_ABBREV_SECTION;
  ElfReader reader(filename, log_flag);
  if (!reader.Open()) {
    return false;
  }
  if (!reader.ReadDebugInfoSection()) {
    return false;
  }
  if (!reader.ReadEhFrameSection()) {
    return false;
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

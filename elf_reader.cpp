#include "elf_reader.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>

#include "dwarf.h"
#include "dwarf_string.h"
#include "read_utils.h"

#define CHECK(expr) \
  if (!(expr)) \
    abort()

static void PrintHex(const char* p, uint64_t len) {
  for (uint64_t i = 0; i < len; ++i) {
    printf("%x ", (unsigned char)p[i]);
  }
  printf("\n");
}

static const char* GetProgramHeaderType(int type) {
  static const std::unordered_map<int, const char*> map = {
    {PT_NULL, "PT_NULL"},
    {PT_LOAD, "PT_LOAD"},
    {PT_DYNAMIC, "PT_DYNAMIC"},
    {PT_INTERP, "PT_INTERP"},
    {PT_NOTE, "PT_NOTE"},
    {PT_SHLIB, "PT_SHLIB"},
    {PT_PHDR, "PT_PHDR"},
    {PT_TLS, "PT_TLS"},
  };
  auto it = map.find(type);
  if (it != map.end()) {
    return it->second;
  }
  return "?";
}

static std::string GetProgramHeaderFlags(int flags) {
  std::string result;
  if (flags & PF_X) {
    result.push_back('X');
  }
  if (flags & PF_W) {
    result.push_back('W');
  }
  if (flags & PF_R) {
    result.push_back('R');
  }
  return result;
}

class FileReadHelper : public ReadHelper {
 public:
  FileReadHelper(FILE* fp, const char* filename)
      : ReadHelper(filename), fp_(fp), fd_(fileno(fp)) {
  }

  ~FileReadHelper() {
    fclose(fp_);
  }

  bool ReadFully(void* buf, size_t size, size_t offset) override {
    ssize_t rc = TEMP_FAILURE_RETRY(pread64(fd_, buf, size, offset));
    if (rc < 0) {
      fprintf(stderr, "failed to read file %s: %s\n", GetName(), strerror(errno));
      return false;
    }
    if (static_cast<size_t>(rc) != size) {
      fprintf(stderr, "requested to read %s for %zu bytes, only get %zd bytes\n",
              GetName(), size, rc);
      return false;
    }
    return true;
  }

 private:
  FILE* fp_;
  int fd_;
};

class MemReadHelper : public ReadHelper {
 public:
  MemReadHelper(const std::vector<char>& data, const char* mem_name)
    : ReadHelper(mem_name), data_(data) {
  }

  bool ReadFully(void* buf, size_t size, size_t offset) override {
    if (offset >= data_.size() || offset + size < offset || offset + size > data_.size()) {
      fprintf(stderr, "failed to read file %s\n", GetName());
      return false;
    }
    memcpy(buf, data_.data() + offset, size);
    return true;
  }

 private:
  const std::vector<char> data_;
};


struct Elf64Struct {
  using Elf_Ehdr = Elf64_Ehdr;
  using Elf_Shdr = Elf64_Shdr;
  using Elf_Phdr = Elf64_Phdr;
  static const int ELFCLASS = ELFCLASS64;
};

struct Elf32Struct {
  using Elf_Ehdr = Elf32_Ehdr;
  using Elf_Shdr = Elf32_Shdr;
  using Elf_Phdr = Elf32_Phdr;
  static const int ELFCLASS = ELFCLASS32;
};

template <typename ElfStruct>
class ElfReaderImpl : public ElfReader {
 public:
  using Elf_Ehdr = typename ElfStruct::Elf_Ehdr;
  using Elf_Shdr = typename ElfStruct::Elf_Shdr;
  using Elf_Phdr = typename ElfStruct::Elf_Phdr;

  ElfReaderImpl(std::unique_ptr<ReadHelper> read_helper, int log_flag)
      : read_helper_(std::move(read_helper)), log_flag_(log_flag),
        read_section_flag_(0) {
  }

  bool Is64() const {
    return ElfStruct::ELFCLASS == ELFCLASS64;
  }

  bool ReadEhFrame() override;
  bool ReadDebugFrame() override;
  bool ReadGnuDebugData() override;

 protected:
  bool ReadHeader() override {
    if (!ReadFully(&header_, sizeof(header_), 0)) {
      return false;
    }
    if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
      fprintf(stderr, "elf magic doesn't match\n");
      return false;
    }
    int elf_class = header_.e_ident[EI_CLASS];
    if (elf_class != ElfStruct::ELFCLASS) {
      fprintf(stderr, "%s is %d-bit elf, doesn't match expected\n",
              read_helper_->GetName(), elf_class == ELFCLASS32 ? 32 : 64);
      return false;
    }
    if (log_flag_ & LOG_HEADER) {
      printf("section offset: %lx\n", (unsigned long)header_.e_shoff);
      printf("section num: %lx\n", (unsigned long)header_.e_shnum);
      printf("section entry size: %lx\n", (unsigned long)header_.e_shentsize);
      printf("string section index: %lu\n", (unsigned long)header_.e_shstrndx);
    }
    return true;
  }

  bool ReadSecHeaders() override {
    if (header_.e_shstrndx == 0) {
      fprintf(stderr, "string section is empty\n");
      return false;
    }
    Elf_Shdr str_sec;
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
      Elf_Shdr sec;
      if (!ReadFully(&sec, sizeof(sec), offset)) {
        return false;
      }
      const char* name = &string_section_[sec.sh_name];
      if (name[0] == '\0') {
        continue;
      }
      sec_headers_[name] = sec;
    }
    if (log_flag_ & LOG_SECTION_HEADERS) {
      for (auto& pair : sec_headers_) {
        printf("section %s, addr %lx, offset %lx, size %lx\n",
               pair.first.c_str(), (unsigned long)pair.second.sh_addr,
               (unsigned long)pair.second.sh_offset,
               (unsigned long)pair.second.sh_size);
      }
    }
    return true;
  }

  bool ReadProgramHeaders() override {
    unsigned long offset = header_.e_phoff;
    for (int i = 0; i < header_.e_phnum; ++i, offset += header_.e_phentsize) {
      Elf_Phdr ph;
      if (!ReadFully(&ph, sizeof(ph), offset)) {
        return false;
      }
      program_headers_.push_back(ph);
    }
    if (log_flag_ & LOG_PROGRAM_HEADERS) {
      for (const auto& ph : program_headers_) {
        printf("program header type %s(%lx) flag (%s)(%lx),offset %lx, vaddr %lx, paddr %lx, size %lx\n",
               GetProgramHeaderType(ph.p_type), (unsigned long)ph.p_type,
               GetProgramHeaderFlags(ph.p_flags).c_str(), (unsigned long)ph.p_flags,
               (unsigned long)ph.p_offset,
               (unsigned long)ph.p_vaddr, (unsigned long)ph.p_paddr,
               (unsigned long)ph.p_filesz);
      }
    }
    return true;
  }

  uint64_t ReadMinVirtualAddress() override {
    uint64_t min_vaddr = ULLONG_MAX;
    for (const auto& ph : program_headers_) {
      if (ph.p_type == PT_LOAD && ph.p_flags & PF_X) {
        if (min_vaddr > ph.p_vaddr) {
          min_vaddr = ph.p_vaddr;
        }
      }
    }
    return min_vaddr;
  }

  bool HasSection(const char* name) override {
    return GetSection(name) != nullptr;
  }

 private:
  bool ReadFully(void* buf, size_t size, size_t offset) {
    return read_helper_->ReadFully(buf, size, offset);
  }

  const Elf_Shdr* GetSection(const char* name) {
    auto it = sec_headers_.find(name);
    if (it != sec_headers_.end()) {
      return &it->second;
    }
    fprintf(stderr, "No %s section in %s\n", name, read_helper_->GetName());
    return nullptr;
  }

  std::vector<char> ReadSection(const Elf_Shdr* section) {
    std::vector<char> data(section->sh_size);
    if (!ReadFully(data.data(), data.size(), section->sh_offset)) {
      return std::vector<char>();
    }
    return data;
  }

  bool ReadEhOrDebugFrame(const Elf_Shdr* sec, const std::vector<char>& data, bool is_eh_frame);

  std::unique_ptr<ReadHelper> read_helper_;
  int log_flag_;
  int read_section_flag_;
  Elf_Ehdr header_;
  std::map<std::string, Elf_Shdr> sec_headers_;
  std::vector<char> string_section_;
  std::vector<Elf_Phdr> program_headers_;
};

template <typename ElfStruct>
bool ElfReaderImpl<ElfStruct>::ReadEhFrame() {
  if (read_section_flag_ & READ_EH_FRAME_SECTION) {
    return true;
  }
  const Elf_Shdr* eh_frame_sec = GetSection(".eh_frame");
  if (eh_frame_sec == nullptr) {
    return false;
  }
  std::vector<char> eh_frame_data = ReadSection(eh_frame_sec);
  if (!ReadEhOrDebugFrame(eh_frame_sec, eh_frame_data, true)) {
    return false;
  }
  read_section_flag_ |= READ_EH_FRAME_SECTION;
  return true;
}

template <typename ElfStruct>
bool ElfReaderImpl<ElfStruct>::ReadDebugFrame() {
  if (read_section_flag_ & READ_DEBUG_FRAME_SECTION) {
    return true;
  }
  const Elf_Shdr* debug_frame_sec = GetSection(".debug_frame");
  if (debug_frame_sec == nullptr) {
    return false;
  }
  std::vector<char> debug_frame_data = ReadSection(debug_frame_sec);
  if (!ReadEhOrDebugFrame(debug_frame_sec, debug_frame_data, false)) {
    return false;
  }
  read_section_flag_ |= READ_DEBUG_FRAME_SECTION;
  return true;
}

static void* xz_alloc(void*, size_t size) {
  return malloc(size);
}

static void xz_free(void*, void* address) {
  free(address);
}

static bool XzDecompress(const std::vector<char>& compressed_data, std::vector<char>* decompressed_data) {
  ISzAlloc alloc;
  CXzUnpacker state;
  alloc.Alloc = xz_alloc;
  alloc.Free = xz_free;
  XzUnpacker_Construct(&state, &alloc);
  CrcGenerateTable();
  Crc64GenerateTable();
  size_t src_offset = 0;
  size_t dst_offset = 0;
  std::vector<char> dst(compressed_data.size(), ' ');

  ECoderStatus status = CODER_STATUS_NOT_FINISHED;
  while (status == CODER_STATUS_NOT_FINISHED) {
    dst.resize(dst.size() * 2);
    size_t src_remaining = compressed_data.size() - src_offset;
    size_t dst_remaining = dst.size() - dst_offset;
    int res = XzUnpacker_Code(&state, reinterpret_cast<Byte*>(&dst[dst_offset]), &dst_remaining,
                              reinterpret_cast<const Byte*>(&compressed_data[src_offset]),
                              &src_remaining, CODER_FINISH_ANY, &status);
    if (res != SZ_OK) {
      fprintf(stderr, "LZMA decompression failed with error %d\n", res);
      XzUnpacker_Free(&state);
      return false;
    }
    src_offset += src_remaining;
    dst_offset += dst_remaining;
  }
  XzUnpacker_Free(&state);
  if (!XzUnpacker_IsStreamWasFinished(&state)) {
    fprintf(stderr, "LZMA decompresstion failed due to incomplete stream\n");
    return false;
  }
  dst.resize(dst_offset);
  *decompressed_data = std::move(dst);
  return true;
}

template <typename ElfStruct>
bool ElfReaderImpl<ElfStruct>::ReadGnuDebugData() {
  if (read_section_flag_ & READ_GNU_DEBUG_DATA_SECTION) {
    return true;
  }
  const Elf_Shdr* gnu_debugdata_sec = GetSection(".gnu_debugdata");
  if (gnu_debugdata_sec == nullptr) {
    return false;
  }
  std::vector<char> gnu_debugdata = ReadSection(gnu_debugdata_sec);
  std::vector<char> decompressed_data;
  if (!XzDecompress(gnu_debugdata, &decompressed_data)) {
    fprintf(stderr, "failed to decompress .gnu_debugdata of %s\n", read_helper_->GetName());
    return false;
  }
  std::string mem_name = std::string(".gnu_debugdata_in_") + read_helper_->GetName();
  std::unique_ptr<ElfReader> reader = ElfReader::OpenMem(decompressed_data, mem_name.c_str(), log_flag_);
  if (reader == nullptr) {
    fprintf(stderr, "can't read elf file %s\n", mem_name.c_str());
    return false;
  }
  if (!reader->ReadDebugFrame()) {
    return false;
  }
  ElfReaderImpl<ElfStruct>* p = reinterpret_cast<ElfReaderImpl<ElfStruct>*>(reader.get());
  cie_table_ = std::move(p->cie_table_);
  fde_table_ = std::move(p->fde_table_);
  read_section_flag_ |= READ_GNU_DEBUG_DATA_SECTION;
  return true;
}

template <typename ElfStruct>
bool ElfReaderImpl<ElfStruct>::ReadEhOrDebugFrame(const Elf_Shdr* sec, const std::vector<char>& data, bool is_eh_frame) {
  const char* begin = data.data();
  const char* end = begin + data.size();
  const char* p;
  if (log_flag_ & LOG_EH_FRAME_SECTION) {
    printf("%s of %s:\n", is_eh_frame ? ".eh_frame" : ".debug_frame", read_helper_->GetName());
    CieTable cie_table;
    for (p = begin; p < end;) {
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
        printf("<%lx> zero terminator\n", (unsigned long)(cie_begin - begin));
        continue;
      }
      const char* cie_end = p + unit_len;
      uint64_t cie_id = Read(p, secbytes);
      if (!section64 && cie_id == DW_CIE_ID_32) {
        cie_id = DW_CIE_ID_64;
      }
      bool is_cie = (is_eh_frame ? cie_id == 0 : cie_id == DW_CIE_ID_64);
      printf("\n<%lx> cie_id %" PRIx64 " %s\n", (unsigned long)(cie_begin - begin), cie_id, is_cie ? "CIE" : "FDE");
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
        uint8_t address_size = Is64() ? 8 : 4; // ELF32 or ELF64
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
              uint64_t personality_handler = ReadEhEncoding(p, encoding, Is64());
              printf("personality pointer 0x%" PRIx64 "\n", personality_handler);
            } else if (c == 'L') {
              uint8_t lsda_encoding = Read(p, 1);
              cie->lsda_encoding = lsda_encoding;
              const char* encoding_str = FindMap(DWARF_EH_ENCODING_MAP, lsda_encoding);
              printf("lsda_encoding 0x%x (%s)\n", lsda_encoding, encoding_str);
            } else if (c == 'S') {
            } else {
              fprintf(stderr, "unexpected augmentation %c\n", c);
              abort();
            }
          }
        }
        // initial_instructions
        printf("initial_instructions len 0x%lx\n", (unsigned long)(cie_end - p));
      } else {
        uint64_t cie_offset = (is_eh_frame ? p - secbytes - begin - cie_id : cie_id);
        printf("cie_offset 0x%" PRIx64 "\n", cie_offset);
        cie = cie_table.FindCie(cie_offset);
        if (cie == nullptr) {
          return false;
        }
        const char* base = p;
        uint64_t initial_location = ReadEhEncoding(p, cie->fde_pointer_encoding, Is64());
        uint64_t address_range = ReadEhEncoding(p, cie->fde_pointer_encoding, Is64());
        printf("initial_location 0x%" PRIx64 ", address_range 0x%" PRIx64"\n",
               initial_location, address_range);
        uint64_t proc_start = initial_location;
        if ((cie->fde_pointer_encoding & 0x70) == DW_EH_PE_pcrel) {
          proc_start += sec->sh_addr + (base - begin);
        }
        printf("proc range [0x%" PRIx64 " - 0x%" PRIx64 "]\n", proc_start, proc_start + address_range);
        current_loc = proc_start;
        if (cie->augmentation[0] == 'z') {
          uint64_t augmentation_len = ReadULEB128(p);
          printf("augmentation_len %" PRIu64 "\n", augmentation_len);
          for (int i = 1; cie->augmentation[i] != '\0'; ++i) {
            if (cie->augmentation[i] == 'L') {
              uint64_t lsda = ReadEhEncoding(p, cie->lsda_encoding, Is64());
              printf("lsda 0x%" PRIx64 "\n", lsda);
            }
          }
        }
        printf("instructions len 0x%lx\n",
               (unsigned long)(cie_end - p));
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
               /*
               if (!ParseDwarfExpression(p, len, section64, cie->address_size)) {
                 return false;
               }
               */
               p += len;
               break;
            }
            case DW_CFA_expression: {
              uint64_t reg = ReadULEB128(p);
              uint64_t len = ReadULEB128(p);
              /*
              if (!ParseDwarfExpression(p, len, section64, cie->address_size)) {
                return false;
              }
              */
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
  }

  for (p = begin; p < end;) {
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
      continue;
    }
    const char* cie_end = p + unit_len;
    uint64_t cie_id = Read(p, secbytes);
    if (!section64 && cie_id == DW_CIE_ID_32) {
      cie_id = DW_CIE_ID_64;
    }
    bool is_cie = (is_eh_frame ? cie_id == 0 : cie_id == DW_CIE_ID_64);
    Cie* cie = nullptr;
    if (is_cie) {
      cie = cie_table_.CreateCie(cie_begin - begin);
      cie->section64 = section64;
      uint8_t version = Read(p, 1);
      const char* augmentation = ReadStr(p);
      cie->augmentation = augmentation;
      CHECK(augmentation[0] == '\0' || augmentation[0] == 'z');
      uint8_t address_size = Is64() ? 8 : 4; // ELF32 or ELF64
      if (version >= 4) {
        address_size = Read(p, 1);
        uint8_t segment_size = Read(p, 1);
      }
      cie->address_size = address_size;
      uint64_t code_alignment_factor = ReadULEB128(p);
      int64_t data_alignment_factor = ReadLEB128(p);
      cie->data_alignment_factor = data_alignment_factor;
      uint64_t return_address_register;
      if (version == 1) {
        return_address_register = Read(p, 1);
      } else {
        return_address_register = ReadULEB128(p);
      }
      if (augmentation[0] == 'z') {
        uint64_t augmentation_len = ReadULEB128(p);
        for (int i = 1; augmentation[i] != '\0'; ++i) {
          char c = augmentation[i];
          if (c == 'R') {
            uint8_t fde_pointer_encoding = Read(p, 1);
            cie->fde_pointer_encoding = fde_pointer_encoding;
          } else if (c == 'P') {
            uint8_t encoding = Read(p, 1);
            uint64_t personality_handler = ReadEhEncoding(p, encoding, Is64());
          } else if (c == 'L') {
            uint8_t lsda_encoding = Read(p, 1);
            cie->lsda_encoding = lsda_encoding;
          } else if (c == 'S') {
            // This is a signal frame
          } else {
            fprintf(stderr, "unexpected augmentation %c\n", c);
            abort();
          }
        }
      }
      // initial_instructions
      cie->insts.insert(cie->insts.begin(), p, cie_end);
    } else {
      uint64_t cie_offset = (is_eh_frame ? p - secbytes - begin - cie_id : cie_id);
      cie = cie_table_.FindCie(cie_offset);
      if (cie == nullptr) {
        return false;
      }
      const char* base = p;
      uint64_t initial_location = ReadEhEncoding(p, cie->fde_pointer_encoding, Is64());
      uint64_t address_range = ReadEhEncoding(p, cie->fde_pointer_encoding, Is64());
      uint64_t proc_start = initial_location;
      if ((cie->fde_pointer_encoding & 0x70) == DW_EH_PE_pcrel) {
        proc_start += sec->sh_addr + (base - begin);
      }
      Fde* fde = fde_table_.CreateFde(proc_start);
      fde->cie = cie;
      fde->section64 = section64;
      fde->func_start = proc_start;
      fde->func_end = proc_start + address_range;
      if (cie->augmentation[0] == 'z') {
        uint64_t augmentation_len = ReadULEB128(p);
        for (int i = 1; cie->augmentation[i] != '\0'; ++i) {
          if (cie->augmentation[i] == 'L') {
            uint64_t lsda = ReadEhEncoding(p, cie->lsda_encoding, Is64());
          }
        }
      }
      fde->insts.insert(fde->insts.begin(), p, cie_end);
    }
    p = cie_end;
  }
  return true;
}

std::unique_ptr<ElfReader> ElfReader::OpenFile(const char* filename, int log_flag) {
  FILE* fp = fopen(filename, "rb");
  if (fp == nullptr) {
    fprintf(stderr, "failed to open %s\n", filename);
    return nullptr;
  }
  std::unique_ptr<ReadHelper> read_helper(new FileReadHelper(fp, filename));
  return Open(std::move(read_helper), log_flag);
}

std::unique_ptr<ElfReader> ElfReader::OpenMem(const std::vector<char>& data,
                                              const char* mem_name, int log_flag) {
  std::unique_ptr<ReadHelper> read_helper(new MemReadHelper(data, mem_name));
  return Open(std::move(read_helper), log_flag);
}

std::unique_ptr<ElfReader> ElfReader::Open(std::unique_ptr<ReadHelper> read_helper,
                                           int log_flag) {
  char buf[EI_NIDENT];
  if (!read_helper->ReadFully(buf, sizeof(buf), 0)) {
    return nullptr;
  }
  if (memcmp(buf, ELFMAG, SELFMAG) != 0) {
    fprintf(stderr, "elf magic is not correct in file %s\n", read_helper->GetName());
    return nullptr;
  }
  int elf_class = buf[EI_CLASS];
  std::unique_ptr<ElfReader> result;
  if (elf_class == ELFCLASS64) {
    result.reset(new ElfReaderImpl<Elf64Struct>(std::move(read_helper), log_flag));
  } else if (elf_class == ELFCLASS32) {
    result.reset(new ElfReaderImpl<Elf32Struct>(std::move(read_helper), log_flag));
  } else {
    fprintf(stderr, "wrong elf class in %s\n", read_helper->GetName());
    return nullptr;
  }
  if (!result->ReadHeader() || !result->ReadSecHeaders() ||
      !result->ReadProgramHeaders()) {
    return nullptr;
  }
  result->ReadMinVaddr();
  return result;
}

std::unordered_map<std::string, std::unique_ptr<ElfReader>>& ElfReaderManager::reader_table_ =
    *new std::unordered_map<std::string, std::unique_ptr<ElfReader>>;

ElfReader* ElfReaderManager::OpenElf(const std::string& filename) {
  auto it = reader_table_.find(filename);
  if (it != reader_table_.end()) {
    return it->second.get();
  }
  reader_table_[filename] = ElfReader::OpenFile(filename.c_str(), 0);
  return reader_table_[filename].get();
}

#ifndef _UNWIND_ELF_READER_H_
#define _UNWIND_ELF_READER_H_

#include <elf.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

struct Cie {
  bool section64;
  uint8_t fde_pointer_encoding;
  uint8_t lsda_encoding;
  int address_size;
  const char* augmentation;
  uint64_t data_alignment_factor;
  std::vector<char> insts;
};

struct Fde {
  Cie* cie;
  bool section64;
  uint64_t func_start;
  uint64_t func_end;
  std::vector<char> insts;
};

class CieTable {
 public:
  CieTable() {
  }

  void operator=(CieTable&& other) {
    for (auto& pair : table_) {
      delete pair.second;
    }
    table_ = std::move(other.table_);
    other.table_.clear();
  }

  ~CieTable() {
    for (auto& pair : table_) {
      delete pair.second;
    }
  }

  Cie* CreateCie(uint64_t offset) {
    Cie*& cie = table_[offset];
    cie = new Cie;
    cie->fde_pointer_encoding = 0;
    cie->lsda_encoding = 0;
    cie->address_size = 0;
    cie->augmentation = nullptr;
    cie->data_alignment_factor = 0;
    return cie;
  }

  Cie* FindCie(uint64_t offset) {
    auto it = table_.find(offset);
    if (it != table_.end()) {
      return it->second;
    }
    fprintf(stderr, "can't find cie at offset 0x%" PRIx64 "\n", offset);
    return nullptr;
  }

 private:
  // From offset in .debug_frame or .eh_frame to CIE.
  // Store Cie* instead of Cie, because we don't want Cie pointers to be invalid
  // after inserting new Cies.
  std::unordered_map<uint64_t, Cie*> table_;

  CieTable(const CieTable&) = delete;
  void operator=(const CieTable&) = delete;
};

class FdeTable {
 public:
  FdeTable() {
  }

  void operator=(FdeTable&& other) {
    table_ = std::move(other.table_);
    other.table_.clear();
  }

  Fde* CreateFde(uint64_t func_start) {
    Fde* fde = &table_[func_start];
    fde->cie = nullptr;
    fde->func_start = func_start;
    fde->func_end = 0;
    return fde;
  }

  Fde* FindFde(uint64_t ip) {
    auto it = table_.upper_bound(ip);
    if (it != table_.begin()) {
      --it;
      return &it->second;
    }
    return nullptr;
  }

 private:
  // From start of function to Fde.
  std::map<uint64_t, Fde> table_;

  FdeTable(const FdeTable&) = delete;
  void operator=(const FdeTable&) = delete;
};

class ReadHelper {
 public:
  ReadHelper(const char* name) : name_(name) {
  }
  virtual ~ReadHelper() {}
  const char* GetName() const {
    return name_.c_str();
  }

  virtual bool ReadFully(void* buf, size_t size, size_t offset) = 0;

 private:
  const std::string name_;
};

class ElfReader {
 protected:
  static const int READ_DEBUG_ABBREV_SECTION = 1;
  static const int READ_DEBUG_STR_SECTION = 2;
  static const int READ_DEBUG_INFO_SECTION = 4;
  static const int READ_EH_FRAME_SECTION = 8;
  static const int READ_DEBUG_FRAME_SECTION = 16;
  static const int READ_GNU_DEBUG_DATA_SECTION = 32;

 public:
  static const int LOG_HEADER = 1;
  static const int LOG_SECTION_HEADERS = 2;
  static const int LOG_DEBUG_ABBREV_SECTION = 4;
  static const int LOG_EH_FRAME_SECTION = 8;
  static const int LOG_PROGRAM_HEADERS = 16;

  static std::unique_ptr<ElfReader> OpenFile(const char* filename, int log_flag);
  static std::unique_ptr<ElfReader> OpenMem(const std::vector<char>& data,
                                            const char* mem_name, int log_flag);

  virtual ~ElfReader() {
  }

  uint64_t GetMinVaddr() const {
    return min_vaddr_;
  }

  Fde* GetFdeForVaddrInFile(uint64_t vaddr_in_file) {
    return fde_table_.FindFde(vaddr_in_file);
  }

  bool ReadUnwindSection() {
    if (HasSection(".debug_frame")) {
      return ReadDebugFrame();
    } else if (HasSection(".gnu_debugdata")) {
      return ReadGnuDebugData();
    } else if (HasSection(".eh_frame")) {
      return ReadEhFrame();
    } else {
      return false;
    }
  }

  virtual bool ReadEhFrame() = 0;
  virtual bool ReadDebugFrame() = 0;
  virtual bool ReadGnuDebugData() = 0;

 protected:
  static std::unique_ptr<ElfReader> Open(std::unique_ptr<ReadHelper> read_helper,
                                         int log_flag);

  ElfReader() : min_vaddr_(0) {
  }

  virtual bool ReadHeader() = 0;
  virtual bool ReadSecHeaders() = 0;
  virtual bool ReadProgramHeaders() = 0;
  virtual uint64_t ReadMinVirtualAddress() = 0;
  virtual bool HasSection(const char* name) = 0;

  CieTable cie_table_;
  FdeTable fde_table_;

 private:
  void ReadMinVaddr() {
    min_vaddr_ = ReadMinVirtualAddress();
  }

  uint64_t min_vaddr_;
};

class ElfReaderManager {
 public:
  static ElfReader* OpenElf(const std::string& filename);
 private:
  static std::unordered_map<std::string, std::unique_ptr<ElfReader>>& reader_table_;
};

#endif  // _UNWIND_ELF_READER_H_

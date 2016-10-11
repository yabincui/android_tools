#include "unwind.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>

#include "dwarf_regmap.h"
#include "dwarf_string.h"
#include "elf_reader.h"
#include "map.h"
#include "read_utils.h"

#define DEBUG_UNWIND

#if defined(DEBUG_UNWIND)
#define D(format, ...) \
    printf(format, ##__VA_ARGS__)
#else
#define D(format...)
#endif

static constexpr int MAX_REGS = 32;

enum class RegStateType {
  UNDEFINED,
  SAME_VALUE,
  OFFSET_N,
  VAL_OFFSET_N,
  REGISTER_R,
  EXPRESSION_E,
  VAL_EXPRESSION_E,
  ARCHITECTURAL,
};

template <class word_t>
struct RegState {
  RegStateType type;
  union {
    struct {
      word_t offset;
    } offset_n;
  };

 void SetOffsetN(word_t offset) {
   type = RegStateType::OFFSET_N;
   offset_n.offset = offset;
 }
};

template <typename word_t>
struct Cfa {
  int regno;
  word_t offset;
};

template <typename word_t>
struct RegValue {
  bool valid;
  word_t value;

  RegValue() : valid(false), value(0) {
  }

  RegValue(word_t value) : valid(true), value(value) {
  }

  void SetValue(word_t value) {
    valid = true;
    this->value = value;
  }
};

template <typename word_t>
class CFAExecutor {
 public:
  CFAExecutor(int sp_regno) : sp_regno_(sp_regno) {
  }

  void Init(Fde* fde, word_t stop_loc) {
    fde_ = fde;
    cie_ = fde->cie;
    if (fde_->section64 != cie_->section64) {
      fprintf(stderr, "fde section64 != cie section64\n");
      abort();
    }
    section64_ = cie_->section64;
    stop_loc_ = stop_loc;
    current_loc_ = fde_->func_start;
    cfa_.regno = -1;
    cfa_.offset = (sizeof(word_t) == 4) ? UINT_MAX : ULLONG_MAX;
    for (int i = 0; i < MAX_REGS; ++i) {
      regs_[i].type = RegStateType::UNDEFINED;
    }
    D("CFAExecutor, fde [0x%" PRIx64 "-0x%" PRIx64 "], stop_loc 0x%" PRIx64 "\n",
      fde_->func_start, fde_->func_end, static_cast<uint64_t>(stop_loc_));
  }

  bool Execute(const RegValue<word_t> old_regs[], RegValue<word_t> new_regs[]);
  bool ExecuteInstructions(const std::vector<char>& insts);

 private:
  const int sp_regno_;
  Fde* fde_;
  Cie* cie_;
  bool section64_;
  word_t stop_loc_;
  word_t current_loc_;
  Cfa<word_t> cfa_;
  RegState<word_t> regs_[MAX_REGS];
};

template <typename word_t>
bool CFAExecutor<word_t>::Execute(const RegValue<word_t> old_regs[], RegValue<word_t> new_regs[]) {
  if (!ExecuteInstructions(cie_->insts)) {
    fprintf(stderr, "execute cie instructions failed\n");
    return false;
  }
  if (!ExecuteInstructions(fde_->insts)) {
    fprintf(stderr, "execute fde instructions failed\n");
    return false;
  }
  if (cfa_.regno == -1 || cfa_.offset == ULLONG_MAX) {
    fprintf(stderr, "cfa not valid\n");
    return false;
  }
  if (cfa_.regno >= MAX_REGS || !old_regs[cfa_.regno].valid) {
    fprintf(stderr, "cfa needs unavailable reg %d\n", cfa_.regno);
    return false;
  }
  word_t cfa_value = old_regs[cfa_.regno].value + cfa_.offset;
  D("cfa reg %d = 0x%" PRIx64 ", offset = 0x%" PRIx64 ", cfa_value = 0x%" PRIx64 "\n",
    cfa_.regno, static_cast<uint64_t>(old_regs[cfa_.regno].value),
    static_cast<uint64_t>(cfa_.offset), static_cast<uint64_t>(cfa_value));
  for (int i = 0; i < MAX_REGS; ++i) {
    new_regs[i].valid = false;
  }
  for (int i = 0; i < MAX_REGS; ++i) {
    RegStateType type = regs_[i].type;
    if (type == RegStateType::UNDEFINED) {
      continue;
    } else if (type == RegStateType::SAME_VALUE) {
      if (old_regs[i].valid) {
        new_regs[i].SetValue(old_regs[i].value);
      }
    } else if (type == RegStateType::OFFSET_N) {
      word_t addr = cfa_value + regs_[i].offset_n.offset;
      word_t value;

      if (cie_->address_size == 4) {
        value = *(uint32_t*)addr;
      } else {
        value = *(uint64_t*)addr;
      }
      new_regs[i].SetValue(value);
    } else {
      fprintf(stderr, "unexpected RegStateType %d\n", type);
      abort();
    }
  }
  // cfa is the sp of the previous frame.
  new_regs[sp_regno_].SetValue(cfa_value);
  return true;
}

template <typename word_t>
bool CFAExecutor<word_t>::ExecuteInstructions(const std::vector<char>& insts) {
  const char* begin = insts.data();
  const char* end = begin + insts.size();
  const char* p = begin;
  while (p < end) {
    uint8_t inst = Read(p, 1);
    D("inst %s (0x%x): ", FindCFAInst(inst), inst);
    if (inst & 0xc0) {
      uint8_t t = inst & 0xc0;
      if (t == DW_CFA_advance_loc) {
        uint8_t delta = inst & 0x3f;
        current_loc_ += delta;
        D("loc = loc + 0x%x = 0x%" PRIx64, delta, static_cast<uint64_t>(current_loc_));
        if (current_loc_ > stop_loc_) {
          break;
        }
      } else if (t == DW_CFA_offset) {
        uint8_t reg = inst & 0x3f;
        uint64_t offset = ReadULEB128(p);
        int64_t add = offset * cie_->data_alignment_factor;
        regs_[reg].SetOffsetN(add);
        if (add >= 0) {
          D("r%u = mem(cfa + 0x%" PRIx64 ")", reg, add);
        } else {
          D("r%u = mem(cfa - 0x%" PRIx64 ")", reg, -add);
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
          uint64_t addr = Read(p, cie_->address_size);
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
          current_loc_ += delta;
          D("loc = loc + 0x%u = 0x%" PRIx64, delta, static_cast<uint64_t>(current_loc_));
          if (current_loc_ > stop_loc_) {
            D("\n");
            return true;
          }
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
          D("r%" PRIu64 " = undefined", reg);
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
          cfa_.regno = reg;
          cfa_.offset = offset;
          D("cfa = r%" PRIu64 " + off 0x%" PRIx64, reg, offset);
          break;
        }
        case DW_CFA_def_cfa_register: {
          uint64_t reg = ReadULEB128(p);
          cfa_.regno = reg;
          D("cfa = r%" PRIu64 " + 0x%" PRIx64, reg, static_cast<uint64_t>(cfa_.offset));
          break;
        }
        case DW_CFA_def_cfa_offset: {
          uint64_t offset = ReadULEB128(p);
          cfa_.offset = offset;
          D("cfa = r%d + off 0x%" PRIx64, cfa_.regno, offset);
          break;
        }
        case DW_CFA_def_cfa_expression: {
           uint64_t len = ReadULEB128(p);
           D("cfa = TODO");
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
    D("\n");
  }
  return true;
}
/*
struct UnwindStruct {
  int reg_count;
  std::unordered_map<int, const char*>& regname_map;
  int ip_regno;
  int sp_regno;
};

static const struct UnwindStruct Unwind_X86_64 {
  .reg_count = X86_64_REG_COUNT,
  .regname_map = X86_64_REG_NAME_MAP,
  .ip_regno = X86_64_RIP,
  .sp_regno = X86_64_RSP,
};

static const struct UnwindStruct Unwind_X86 {
  .reg_count = X86_REG_COUNT,
  .regname_map = X86_REG_NAME_MAP,
  .ip_regno = X86_RIP,
  .sp_regno = X86_RSP,
};

static const struct UnwindStruct Unwind_AARCH64 {
  .reg_count = AARCH64_REG_COUNT,
  .regname_map = AARCH64_REG_NAME_MAP,
  .ip_regno = AARCH64_RIP,
  .sp_regno = AARCH64_RSP,
};

static const struct UnwindStruct Unwind_ARM {
  .reg_count = ARM_REG_COUNT,
  .regname_map = ARM_REG_NAME_MAP,
  .ip_regno = ARM_RIP,
  .sp_regno = ARM_RSP,
};
*/

struct UnwindStruct_X86_64 {
  static const int reg_count = X86_64_REG_COUNT;
  static const std::unordered_map<int, const char*>& regname_map;
  static const int ip_regno = X86_64_RIP;
  static const int sp_regno = X86_64_RSP;
  using word_t = uint64_t;
};
const std::unordered_map<int, const char*>& UnwindStruct_X86_64::regname_map = X86_64_REG_NAME_MAP;

struct UnwindStruct_X86 {
  static const int reg_count = X86_REG_COUNT;
  static const std::unordered_map<int, const char*>& regname_map;
  static const int ip_regno = X86_EIP;
  static const int sp_regno = X86_ESP;
  using word_t = uint32_t;
};
const std::unordered_map<int, const char*>& UnwindStruct_X86::regname_map = X86_REG_NAME_MAP;


struct UnwindStruct_AARCH64 {
  static const int reg_count = AARCH64_REG_COUNT;
  static const std::unordered_map<int, const char*>& regname_map;
  static const int ip_regno = AARCH64_IP;
  static const int sp_regno = AARCH64_SP;
  using word_t = uint64_t;
};
const std::unordered_map<int, const char*>& UnwindStruct_AARCH64::regname_map = AARCH64_REG_NAME_MAP;

struct UnwindStruct_ARM {
  static const int reg_count = ARM_REG_COUNT;
  static const std::unordered_map<int, const char*>& regname_map;
  static const int ip_regno = ARM_LR;
  static const int sp_regno = ARM_SP;
  using word_t = uint32_t;
};
const std::unordered_map<int, const char*>& UnwindStruct_ARM::regname_map = ARM_REG_NAME_MAP;

extern "C" void GetCurrentRegs(void* mc);

// Unwind steps:
// 1. GetMContext
// 2. Get map and map ip to dso and vaddr_in_file.
// 3. get fde for current ip
// 4. build a virtual table
// 3. execute dwarf cfa instructions to ip
// 4. get cfa value and register values
template <typename UnwindStruct>
bool UnwindInner() {
  using word_t = typename UnwindStruct::word_t;
  word_t current_regs[MAX_REGS];

  GetCurrentRegs(current_regs);

  RegValue<word_t> reg_values[MAX_REGS];

  for (int i = 0; i < UnwindStruct::reg_count; ++i) {
    reg_values[i].SetValue(current_regs[i]);
    D("reg[%s] = 0x%" PRIx64 "\n", FindMap(UnwindStruct::regname_map, i), static_cast<uint64_t>(reg_values[i].value));
  }

  MapTree map_tree;
  map_tree.UpdateMaps();

  RegValue<word_t> reg_values2[MAX_REGS];
  RegValue<word_t>* rp1 = reg_values;
  RegValue<word_t>* rp2 = reg_values2;
  CFAExecutor<word_t> executor(UnwindStruct::sp_regno);
  while (rp1[UnwindStruct::ip_regno].valid) {
    word_t ip = rp1[UnwindStruct::ip_regno].value;
    printf("ip 0x%" PRIx64 "\n", static_cast<uint64_t>(ip));
    Map* map = map_tree.GetMapForIp(ip);
    if (map == nullptr) {
      fprintf(stderr, "can't get map for ip\n");
      return false;
    }
    printf("map: [0x%" PRIx64 " - 0x%" PRIx64 "], dso %s\n", map->start, map->end, map->dso.c_str());
    if (map->dso_reader == nullptr) {
      map->dso_reader = ElfReaderManager::OpenElf(map->dso);
      if (map->dso_reader == nullptr) {
        fprintf(stderr, "failed to read dso %s\n", map->dso.c_str());
        return false;
      }
    }
    word_t vaddr_in_file = ip - map->start + map->dso_reader->GetMinVaddr();
    D("vaddr_in_file = 0x%" PRIx64 "\n", static_cast<uint64_t>(vaddr_in_file));
    if (!map->dso_reader->ReadEhFrame()) {
      return false;
    }
    Fde* fde = map->dso_reader->GetFdeForVaddrInFile(vaddr_in_file);
    if (fde == nullptr) {
      fprintf(stderr, "can't get fde for vaddr\n");
      return false;
    }
    D("fde func[0x%" PRIx64 "-0x%" PRIx64 "]\n", fde->func_start, fde->func_end);
    executor.Init(fde, vaddr_in_file);
    if (!executor.Execute(rp1, rp2)) {
      return false;
    }
    for (int i = 0; i < MAX_REGS; ++i) {
      const char* name = FindMap(UnwindStruct::regname_map, i);
      D("rp2[%s(%d)] = %d, 0x%" PRIx64 "\n", name, i, rp2[i].valid, static_cast<uint64_t>(rp2[i].value));
    }
    RegValue<word_t>* tmp = rp1;
    rp1 = rp2;
    rp2 = tmp;
  }
  return true;
}

bool Unwind() {
#if defined(__x86_64__)
  return UnwindInner<UnwindStruct_X86_64>();
#elif defined(__i386__)
  return UnwindInner<UnwindStruct_X86>();
#elif defined(__aarch64__)
  return UnwindInner<UnwindStruct_AARCH64>();
#elif defined(__arm__)
  return UnwindInner<UnwindStruct_ARM>();
#else
  return false;
#endif
}

void funcInBetween() {
  Unwind();
}

int main() {

  funcInBetween();
  return 0;
}

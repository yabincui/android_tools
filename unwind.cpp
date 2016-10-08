#include "unwind.h"

#include <inttypes.h>
#include <stdio.h>
#include <ucontext.h>

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

static constexpr int MAX_REGS = 64;

enum class RegState {
  UNDEFINED,
  SAME_VALUE,
  OFFSET_N,
  VAL_OFFSET_N,
  REGISTER_R,
  EXPRESSION_E,
  VAL_EXPRESSION_E,
  ARCHITECTURAL,
};

struct Reg {
  RegState state;
  union {
    struct {
      uint64_t offset;
    } offset_n;
  };

 void SetOffsetN(uint64_t offset) {
   state = RegState::OFFSET_N;
   offset_n.offset = offset;
 }
};

struct Cfa {
  int regno;
  uint64_t offset;
};

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

class CFAExecutor {
 public:
  void Init(Fde* fde, uint64_t stop_loc) {
    fde_ = fde;
    cie_ = fde->cie;
    if (fde_->section64 != cie_->section64) {
      fprintf(stderr, "fde section64 != cie section64\n");
      abort();
    }
    section64_ = cie_->section64;
    stop_loc_ = stop_loc;
    current_loc_ = fde_->func_start;
    cfa_.regno = 0;
    cfa_.offset = 0;
    for (int i = 0; i < MAX_REGS; ++i) {
      regs_[i].state = RegState::UNDEFINED;
    }
    D("CFAExecutor, fde [0x%" PRIx64 "-0x%" PRIx64 "], stop_loc 0x%" PRIx64 "\n",
      fde_->func_start, fde_->func_end, stop_loc_);
  }

  bool Execute();
  bool ExecuteInstructions(const std::vector<char>& insts);

 private:
  Fde* fde_;
  Cie* cie_;
  bool section64_;
  uint64_t stop_loc_;
  uint64_t current_loc_;
  Cfa cfa_;
  Reg regs_[MAX_REGS];
};

bool CFAExecutor::Execute() {
  if (!ExecuteInstructions(cie_->insts)) {
    return false;
  }
  if (!ExecuteInstructions(fde_->insts)) {
    return false;
  }
  return true;
}

bool CFAExecutor::ExecuteInstructions(const std::vector<char>& insts) {
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
        D("loc = loc + 0x%x = 0x%" PRIx64, delta, current_loc_);
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
          D("loc = loc + 0x%u = 0x%" PRIx64, delta, current_loc_);
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
          D("cfa = r%" PRIu64 " + 0x%" PRIx64, reg, cfa_.offset);
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

extern "C" void GetMContext(mcontext_t* mc);

// Unwind steps:
// 1. GetMContext
// 2. Get map and map ip to dso and vaddr_in_file.
// 3. get fde for current ip
// 4. build a virtual table
// 3. execute dwarf cfa instructions to ip
// 4. get cfa value and register values
void Unwind() {
  mcontext_t mc;
  GetMContext(&mc);
  D("r8 0x%llx\n", mc.gregs[REG_R8]);
  D("r9 0x%llx\n", mc.gregs[REG_R9]);
  D("r10 0x%llx\n", mc.gregs[REG_R10]);
  D("r11 0x%llx\n", mc.gregs[REG_R11]);
  D("r12 0x%llx\n", mc.gregs[REG_R12]);
  D("r13 0x%llx\n", mc.gregs[REG_R13]);
  D("r14 0x%llx\n", mc.gregs[REG_R14]);
  D("r15 0x%llx\n", mc.gregs[REG_R15]);
  D("rdi 0x%llx\n", mc.gregs[REG_RDI]);
  D("rsi 0x%llx\n", mc.gregs[REG_RSI]);
  D("rbp 0x%llx\n", mc.gregs[REG_RBP]);
  D("rbx 0x%llx\n", mc.gregs[REG_RBX]);
  D("rdx 0x%llx\n", mc.gregs[REG_RDX]);
  D("rax 0x%llx\n", mc.gregs[REG_RAX]);
  D("rcx 0x%llx\n", mc.gregs[REG_RCX]);
  D("rsp 0x%llx\n", mc.gregs[REG_RSP]);
  D("rip 0x%llx\n", mc.gregs[REG_RIP]);

  uint64_t ip = mc.gregs[REG_RIP] - 1;
  MapTree map_tree;
  map_tree.UpdateMaps();
  Map* map = map_tree.GetMapForIp(ip);
  if (map == nullptr) {
    fprintf(stderr, "can't get map for ip\n");
    return;
  }
  printf("map: [0x%" PRIx64 " - 0x%" PRIx64 "], dso %s\n", map->start, map->end, map->dso.c_str());
  if (map->dso_reader == nullptr) {
    map->dso_reader = ElfReaderManager::OpenElf(map->dso);
    if (map->dso_reader == nullptr) {
      fprintf(stderr, "failed to read dso %s\n", map->dso.c_str());
      return;
    }
  }
  uint64_t vaddr_in_file = ip - map->start + map->dso_reader->GetMinVaddr();
  printf("vaddr_in_file = 0x%" PRIx64 "\n", vaddr_in_file);
  if (!map->dso_reader->ReadEhFrame()) {
    return;
  }
  Fde* fde = map->dso_reader->GetFdeForVaddrInFile(vaddr_in_file);
  if (fde == nullptr) {
    fprintf(stderr, "can't get fde for vaddr\n");
    return;
  }
  printf("fde func[0x%" PRIx64 "-0x%" PRIx64 "]\n", fde->func_start, fde->func_end);
  CFAExecutor executor;
  executor.Init(fde, vaddr_in_file);
  executor.Execute();
}

int main() {
  Unwind();
  return 0;
}

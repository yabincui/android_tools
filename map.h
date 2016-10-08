#ifndef _UNWIND_MAP_H_
#define _UNWIND_MAP_H_

#include <sys/types.h>

#include <map>
#include <memory>
#include <string>

#include "elf_reader.h"

struct Map {
  uint64_t start;
  uint64_t end;
  std::string dso;
  ElfReader* dso_reader;
};

// Maps of current process, the maps are update regularly, like 0.3HZ.
class MapTree {
 public:

  bool UpdateMaps();
  Map* GetMapForIp(uint64_t ip) {
    auto it = map_table_.upper_bound(ip);
    if (it != map_table_.begin()) {
      --it;
      if (it->second.start <= ip && it->second.end > ip) {
        return &it->second;
      }
    }
    return nullptr;
  }

 private:
  std::map<uint64_t, Map> map_table_;
};

#endif  // _UNWIND_MAP_H_

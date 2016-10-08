#include "map.h"

#include <inttypes.h>
#include <string.h>

#include <vector>

class LineReader {
 public:
  explicit LineReader(FILE* fp) : fp_(fp), buf_(nullptr), bufsize_(0) {
  }

  ~LineReader() {
    free(buf_);
    fclose(fp_);
  }

  char* ReadLine() {
    if (getline(&buf_, &bufsize_, fp_) != -1) {
      return buf_;
    }
    return nullptr;
  }

  size_t MaxLineSize() {
    return bufsize_;
  }

 private:
  FILE* fp_;
  char* buf_;
  size_t bufsize_;
};

bool GetThreadMmapsInProcess(std::map<uint64_t, Map>* maps) {
  FILE* fp = fopen("/proc/self/maps", "re");
  if (fp == nullptr) {
    fprintf(stderr, "can't open /proc/self/maps");
    return false;
  }
  LineReader reader(fp);
  char* line;
  while ((line = reader.ReadLine()) != nullptr) {
    // Parse line like: 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
    uint64_t start_addr, end_addr, pgoff;
    char type[reader.MaxLineSize()];
    char execname[reader.MaxLineSize()];
    execname[0] = '\0';
    if (sscanf(line, "%" PRIx64 "-%" PRIx64 " %s %" PRIx64 " %*x:%*x %*u %s\n", &start_addr,
               &end_addr, type, &pgoff, execname) < 4) {
      continue;
    }
    if (type[2] != 'x') {
      continue;
    }
    if (execname[0] == '\0') {
      // can't handle anonymous executable
      continue;
    }
    Map& map = (*maps)[start_addr];
    map.start = start_addr;
    map.end = end_addr;
    map.dso = execname;
    map.dso_reader = nullptr;
  }
  return true;
}

// Read /proc/self/maps to update maps.
bool MapTree::UpdateMaps() {
  std::map<uint64_t, Map> maps;
  if (!GetThreadMmapsInProcess(&maps)) {
    return false;
  }
  map_table_ = std::move(maps);
  return true;
}

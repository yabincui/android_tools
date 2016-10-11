#include <stdio.h>
#include <stdlib.h>

#include "elf_reader.h"

bool ReadElf(const char* filename) {
  std::unique_ptr<ElfReader> reader = ElfReader::Create(filename, -1);
  if (!reader->ReadEhFrame()) {
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
  if (!ReadElf(filename)) {
    fprintf(stderr, "failed to read %s\n", filename);
    return 1;
  }
  return 0;
}

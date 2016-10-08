#ifndef _UNWIND_READ_UTILS_H_
#define _UNWIND_READ_UTILS_H_

#include <stdio.h>
#include <string.h>

#include "dwarf.h"

static inline int64_t ReadLEB128(const char*& p) {
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

static inline uint64_t ReadULEB128(const char*& p) {
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

static inline uint64_t Read(const char*& p, int size) {
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

static inline int64_t ReadS(const char*& p, int size) {
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

static inline const char* ReadStr(const char*& p) {
  const char* result = p;
  p += strlen(p) + 1;
  return result;
}

static inline uint64_t ReadEhEncoding(const char*& p, uint8_t encoding) {
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

#endif  // _UNWIND_READ_UTILS_H_

// https://monoinfinito.wordpress.com/series/exception-handling-in-c/
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define DEBUG

#if defined(DEBUG)
#define D(format,...) \
  printf(format,##__VA_ARGS__)
#else
#define D(format,...)
#endif

namespace __cxxabiv1 {
    struct __class_type_info {
      virtual void foo() {}
    } ti;
}

#define EXCEPTION_BUFF_SIZE 255
static char exception_buff[EXCEPTION_BUFF_SIZE];

extern "C" {
void* __cxa_allocate_exception(size_t thrown_size) {
  D("alloc ex %zu\n", thrown_size);
  if (thrown_size > EXCEPTION_BUFF_SIZE) {
    D("Exception too big\n");
    abort();
  }
  D("exception_buff pointer = %p\n", &exception_buff);
  return &exception_buff;
}

void __cxa_free_exception(void* thrown_exception);

#include <unwind.h>
#include <typeinfo>

typedef void (*unexpected_handler)();
typedef void (*terminate_handler)();

struct __cxa_exception {
  std::type_info* exceptionType;
  void (*exceptionDestructor)(void*);
  unexpected_handler unexpectedHandler;
  terminate_handler terminateHandler;
  __cxa_exception* nextException;

  int handlerCount;
  int handlerSwitchValue;
  const char* actionRecord;
  const char* languageSpecificData;
  void* catchTemp;
  void* adjustedPtr;
  _Unwind_Exception unwindHeader;
};

#define container_of(p, global_struct, member) \
  (global_struct*)(((uintptr_t)p) - (uintptr_t)(&((global_struct*)0)->member))

void __cxa_throw(void* thrown_exception,
                 std::type_info* tinfo,
                 void (*dest)(void*)) {
  D("__cxa_throw called, thrown_exception = %p\n", thrown_exception);
  __cxa_exception* header = ((__cxa_exception*)thrown_exception);
  header->exceptionType = tinfo;
  D("header = %p, &header->unwindHeader = %p\n", header, &header->unwindHeader);
  _Unwind_RaiseException(&header->unwindHeader);
  D("no one handled __cxa_throw, terminate\n");
  exit(0);
}

void __cxa_begin_catch() {
  D("begin catch\n");
}

void __cxa_end_catch() {
  D("end catch\n");
}

typedef unsigned long long uleb128_t;

static uleb128_t ReadUleb128(const uint8_t*& p) {
  uleb128_t result = 0;
  int shift = 0;
  while (*p & 0x80) {
    result |= (*p & 0x7f) << shift;
    shift += 7;
    p++;
  }
  result |= (*p & 0x7f) << shift;
  p++;
  return result;
}

// structure in .gcc_except_table
struct LSDA_Header {
  uint8_t lsda_start_encoding;
  uint8_t lsda_type_encoding;
  uleb128_t type_table_offset; // from next position
  uint8_t call_site_encoding;
  uleb128_t call_site_length;

  const uint8_t* call_site_start;
  const uint8_t* call_site_end;
  const uint8_t* action_table;
  const uint32_t* type_table;

  LSDA_Header(const uint8_t*& ptr) {
    lsda_start_encoding = *ptr++;
    lsda_type_encoding = *ptr++;
    if (lsda_type_encoding == 0xff) {
      type_table_offset = 0;
      type_table = NULL;
    } else {
      type_table_offset = ReadUleb128(ptr);
      type_table = (const uint32_t*)(ptr + type_table_offset);
    }
    call_site_encoding = *ptr++;
    call_site_length = ReadUleb128(ptr);
    call_site_start = ptr;
    call_site_end = ptr + call_site_length;
    action_table = ptr + call_site_length;
  }
};

struct LSDA_Call_Site {
  LSDA_Call_Site(const uint8_t*& ptr) {
    cs_start = ReadUleb128(ptr);
    cs_len = ReadUleb128(ptr);
    cs_lp = ReadUleb128(ptr);
    cs_action = ReadUleb128(ptr);
  }

  uleb128_t cs_start;
  uleb128_t cs_len;
  uleb128_t cs_lp;  // landing pad position
  uleb128_t cs_action;  // cs.action is the offset + 1; cs.action == 0 means
    // there is no associated entry in the action table.
};

_Unwind_Reason_Code __gxx_personality_v0 (int version, _Unwind_Action actions,
                                          uint64_t exceptionClass,
                                          _Unwind_Exception* unwind_exception,
                                          _Unwind_Context* context) {
  D("personality function_v0\n");
  if (actions & (_UA_SEARCH_PHASE | _UA_CLEANUP_PHASE)) {
    if (actions & _UA_SEARCH_PHASE) {
      D("lookup phase\n");
    } else {
      D("cleanup phase\n");
    }
    __cxa_exception* exception_header = container_of(unwind_exception, __cxa_exception, unwindHeader);
    const char* type_name = exception_header->exceptionType->name();
    uintptr_t throw_ip = _Unwind_GetIP(context) - 1;
    uintptr_t func_start = _Unwind_GetRegionStart(context);
    const uint8_t* lsda = (const uint8_t*)_Unwind_GetLanguageSpecificData(context);

    LSDA_Header header(lsda);
    const uint8_t* p;
    size_t i;
    D("throw_ip = %lx\n", (unsigned long)throw_ip);
    D("func_start = %lx\n", (unsigned long)func_start);
    D("lsda_start_encoding = %x\n", header.lsda_start_encoding);
    D("type_table_offset = %llx\n", header.type_table_offset);
    D("call_site_length = %lld\n", header.call_site_length);
    for (i = 0, p = header.call_site_start; p < header.call_site_end; i++) {
      LSDA_Call_Site cs(p);
      D("Found a CS:\n");
      D("\tcs_start: %llx\n", cs.cs_start);
      D("\tcs_len: %llx\n", cs.cs_len);
      D("\tcs_lp: %llx\n", cs.cs_lp);
      D("\tcs_action: %llx\n", cs.cs_action);
      if (cs.cs_lp == 0) {
        continue;
      }
      if (func_start + cs.cs_start > throw_ip || throw_ip >= func_start + cs.cs_start + cs.cs_len) {
        continue;
      }
      if (cs.cs_action == 0 && (actions & _UA_SEARCH_PHASE)) {
        continue;
      }
      bool found = (cs.cs_action == 0);
      int type_index;
      int action_index;
      int action_position = 1;
      if (cs.cs_action != 0) {
        type_index = header.action_table[cs.cs_action - 1];
        action_index = cs.cs_action - 1;
      }
      while (!found) {
        D("\ttype_index: %d\n", type_index);
        if (type_index == 0) {
          if (actions & _UA_CLEANUP_PHASE) {
            found = true;
          }
          break;
        }
        uint32_t catch_type_info = header.type_table[-1 * type_index];
        const std::type_info* catch_ti = (const std::type_info*)(uint64_t)catch_type_info;
        D("%s\n", catch_ti->name());
        if (catch_ti->name() == type_name) {
          found = true;
          break;
        }
        action_index++;
        if (header.action_table[action_index] == 0) {
          break;
        }
        action_index += header.action_table[action_index];
        if (action_index >= 128) {
          action_index -= 128;
        }
        type_index = header.action_table[action_index];
        action_position++;
      }
      if (!found) {
        continue;
      }
      if (actions & _UA_SEARCH_PHASE) {
        return _URC_HANDLER_FOUND;
      }
      int r0 = __builtin_eh_return_data_regno(0);
      int r1 = __builtin_eh_return_data_regno(1);
      _Unwind_SetGR(context, r0, (uintptr_t)(unwind_exception));
      _Unwind_SetGR(context, r1, (uintptr_t)(action_position));
      _Unwind_SetIP(context, func_start + cs.cs_lp);
      return _URC_INSTALL_CONTEXT;
    }
    return _URC_CONTINUE_UNWIND;
  } else {
    D("error actions %x\n", actions);
    return _URC_FATAL_PHASE1_ERROR;
  }
}

}

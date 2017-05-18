#ifndef _ARM_EXCEPTION_H_
#define _ARM_EXCEPTION_H_

static constexpr int EXIDX_CANTUNWIND = 0x1;

static constexpr uint8_t ARMEX_REFUSE_TO_UNWIND_BYTE1 = 0x80;
static constexpr uint8_t ARMEX_REFUSE_TO_UNWIND_BYTE2 = 0x00;
static constexpr uint8_t ARMEX_FINISH = 0xb0;


#endif

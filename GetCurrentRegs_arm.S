#define ARM_R0  0x00
#define ARM_R1  0x04
#define ARM_R2  0x08
#define ARM_R3  0x0c
#define ARM_R4  0x10
#define ARM_R5  0x14
#define ARM_R6  0x18
#define ARM_R7  0x1c
#define ARM_R8  0x20
#define ARM_R9  0x24
#define ARM_R10  0x28
#define ARM_R11  0x2c
#define ARM_R12  0x30
#define ARM_SP  0x34
#define ARM_LR  0x38
#define ARM_PC  0x3c


// GetCurrentRegs(uint32_t* regs)
  .global GetCurrentRegs
  .type GetCurrentRegs, %function
GetCurrentRegs:
  .cfi_startproc

  stmib r0, {r0-r12}
  mov r1, sp
  str r1, [r0, ARM_SP]
  add r1, lr, #4
  str r1, [r0, ARM_LR]
  str r1, [r0, ARM_PC]
  mov r0, #0
  bx lr
  .cfi_endproc

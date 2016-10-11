#define AARCH64_X0  0x00
#define AARCH64_X1  0x08
#define AARCH64_X2  0x10
#define AARCH64_X3  0x18
#define AARCH64_X4  0x20
#define AARCH64_X5  0x28
#define AARCH64_X6  0x30
#define AARCH64_X7  0x38
#define AARCH64_X8  0x40
#define AARCH64_X9  0x48
#define AARCH64_X10  0x50
#define AARCH64_X11  0x58
#define AARCH64_X12  0x60
#define AARCH64_X13  0x68
#define AARCH64_X14  0x70
#define AARCH64_X15  0x78
#define AARCH64_X16  0x80
#define AARCH64_X17  0x88
#define AARCH64_X18  0x90
#define AARCH64_X19  0x98
#define AARCH64_X20  0xa0
#define AARCH64_X21  0xa8
#define AARCH64_X22  0xb0
#define AARCH64_X23  0xb8
#define AARCH64_X24  0xc0
#define AARCH64_X25  0xc8
#define AARCH64_X26  0xd0
#define AARCH64_X27  0xd8
#define AARCH64_X28  0xe0
#define AARCH64_X29  0xe8
#define AARCH64_IP  0xf0
#define AARCH64_SP  0xf8

// GetCurrentRegs(uint64_t* regs)
  .global GetCurrentRegs
  .type GetCurrentRegs, @function
GetCurrentRegs:
  .cfi_startproc

  // TODO: these registers may not needed as they are not saved by callee.
  stp xzr, x1, [x0, AARCH64_X0]
  stp x2, x3, [x0, AARCH64_X2]
  stp x4, x5, [x0, AARCH64_X4]
  stp x6, x7, [x0, AARCH64_X6]
  stp x8, x9, [x0, AARCH64_X8]
  stp x10, x11, [x0, AARCH64_X10]
  stp x12, x13, [x0, AARCH64_X12]
  stp x14, x15, [x0, AARCH64_X14]
  stp x16, x17, [x0, AARCH64_X16]

  stp x18, x19, [x0, AARCH64_X18]
  stp x20, x21, [x0, AARCH64_X20]
  stp x22, x23, [x0, AARCH64_X22]
  stp x24, x25, [x0, AARCH64_X24]
  stp x26, x27, [x0, AARCH64_X26]
  stp x28, x29, [x0, AARCH64_X28]
  mov x1, sp
  stp x30, x1, [x0, AARCH64_IP]

  mov x0, 0
  ret
  .cfi_endproc

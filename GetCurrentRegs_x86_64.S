#define X86_64_RAX 0x00
#define X86_64_RDX 0x08
#define X86_64_RCX 0x10
#define X86_64_RBX 0x18
#define X86_64_RSI 0x20
#define X86_64_RDI 0x28
#define X86_64_RBP 0x30
#define X86_64_RSP 0x38
#define X86_64_R8 0x40
#define X86_64_R9 0x48
#define X86_64_R10 0x50
#define X86_64_R11 0x58
#define X86_64_R12 0x60
#define X86_64_R13 0x68
#define X86_64_R14 0x70
#define X86_64_R15 0x78
#define X86_64_RIP 0x80

// GetCurrentRegs(uint64_t* regs)
  .global GetCurrentRegs
  .type GetCurrentRegs, @function
GetCurrentRegs:
  .cfi_startproc
  // %rdi first argument register

  /* Callee saved: RBX, RBP, R12-R15  */
  movq %r12, X86_64_R12(%rdi)
  movq %r13, X86_64_R13(%rdi)
  movq %r14, X86_64_R14(%rdi)
  movq %r15, X86_64_R15(%rdi)
  movq %rbp, X86_64_RBP(%rdi)
  movq %rbx, X86_64_RBX(%rdi)

  /* Save argument registers (not strictly needed, but setcontext
     restores them, so don't restore garbage).  */
  movq %r8,  X86_64_R8(%rdi)
  movq %r9,  X86_64_R9(%rdi)
  movq %rdi, X86_64_RDI(%rdi)
  movq %rsi, X86_64_RSI(%rdi)
  movq %rdx, X86_64_RDX(%rdi)
  movq %rax, X86_64_RAX(%rdi)
  movq %rcx, X86_64_RCX(%rdi)

  leaq 8(%rsp), %rax /* exclude this call.  */
  movq %rax, X86_64_RSP(%rdi)

  movq 0(%rsp), %rax
  movq %rax, X86_64_RIP(%rdi)

  xorq  %rax, %rax
  retq
  .cfi_endproc

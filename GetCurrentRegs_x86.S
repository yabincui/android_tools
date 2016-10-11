#define X86_EAX 0x00
#define X86_EDX 0x04
#define X86_ECX 0x08
#define X86_EBX 0x0c
#define X86_ESP 0x10
#define X86_EBP 0x14
#define X86_ESI 0x18
#define X86_EDI 0x1c
#define X86_EIP 0x20

// GetCurrentRegs(uint32_t* regs)
  .global GetCurrentRegs
  .type GetCurrentRegs, @function
GetCurrentRegs:
  .cfi_startproc
  mov 4(%esp), %eax
  movl $0, X86_EAX(%eax)
  movl %ebx, X86_EBX(%eax)
  movl %ecx, X86_ECX(%eax)
  movl %edx, X86_EDX(%eax)
  movl %edi, X86_EDI(%eax)
  movl %esi, X86_ESI(%eax)
  movl %ebp, X86_EBP(%eax)
  movl (%esp), %ecx
  movl %ecx, X86_EIP(%eax)
  leal 4(%esp), %ecx
  movl %ecx, X86_ESP(%eax)
  xor %eax, %eax
  ret
  .cfi_endproc

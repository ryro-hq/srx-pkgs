// SPDX-License-Identifier: Apache-2.0
// No libc, startup objects or interpreter: exercise the declared assembler/linker.
.global _start
.text
_start:
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_end-message, %edx
    syscall
    cmp $message_end-message, %rax
    jne failed
    xor %edi, %edi
    jmp finish
failed:
    mov $1, %edi
finish:
    mov $60, %eax
    syscall
.section .rodata
message:
    .ascii "SRX source-built binutils\n"
message_end:
.section .note.GNU-stack,"",@progbits

# SPDX-License-Identifier: Apache-2.0
# Qualification input: explicit tools, no built-in compiler rules or shell code.
define ASSEMBLY
.global _start
.text
_start:
 mov $$60, %eax
 xor %edi, %edi
 syscall
.section .note.GNU-stack,"",@progbits
endef
$(file >probe.s,$(ASSEMBLY))
.PHONY: all
all: probe

probe: probe.o
	$(LD) -static --build-id=none -e _start -o probe probe.o

probe.o: probe.s
	$(AS) --64 -o probe.o probe.s

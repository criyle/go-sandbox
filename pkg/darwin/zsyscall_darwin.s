#include "textflag.h"
TEXT ·libc_sandbox_init_trampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_init(SB)

TEXT ·libc_sandbox_free_error_trampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_free_error(SB)

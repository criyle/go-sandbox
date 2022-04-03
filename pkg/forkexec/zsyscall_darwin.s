#include "textflag.h"

TEXT libc_sandbox_init_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_init(SB)

GLOBL	·libc_sandbox_init_trampoline_addr(SB), RODATA, $8
DATA	·libc_sandbox_init_trampoline_addr(SB)/8, $libc_sandbox_init_trampoline<>(SB)

TEXT libc_sandbox_free_error_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_free_error(SB)

GLOBL	·libc_sandbox_free_error_trampoline_addr(SB), RODATA, $8
DATA	·libc_sandbox_free_error_trampoline_addr(SB)/8, $libc_sandbox_free_error_trampoline<>(SB)

TEXT libc_fork_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_fork(SB)

GLOBL	·libc_fork_trampoline_addr(SB), RODATA, $8
DATA	·libc_fork_trampoline_addr(SB)/8, $libc_fork_trampoline<>(SB)

TEXT libc_close_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_close(SB)

GLOBL	·libc_close_trampoline_addr(SB), RODATA, $8
DATA	·libc_close_trampoline_addr(SB)/8, $libc_close_trampoline<>(SB)

TEXT libc_read_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_read(SB)

GLOBL	·libc_read_trampoline_addr(SB), RODATA, $8
DATA	·libc_read_trampoline_addr(SB)/8, $libc_read_trampoline<>(SB)

TEXT libc_write_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_write(SB)

GLOBL	·libc_write_trampoline_addr(SB), RODATA, $8
DATA	·libc_write_trampoline_addr(SB)/8, $libc_write_trampoline<>(SB)

TEXT libc_fcntl_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_fcntl(SB)

GLOBL	·libc_fcntl_trampoline_addr(SB), RODATA, $8
DATA	·libc_fcntl_trampoline_addr(SB)/8, $libc_fcntl_trampoline<>(SB)

TEXT libc_dup2_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_dup2(SB)

GLOBL	·libc_dup2_trampoline_addr(SB), RODATA, $8
DATA	·libc_dup2_trampoline_addr(SB)/8, $libc_dup2_trampoline<>(SB)

TEXT libc_chdir_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_chdir(SB)

GLOBL	·libc_chdir_trampoline_addr(SB), RODATA, $8
DATA	·libc_chdir_trampoline_addr(SB)/8, $libc_chdir_trampoline<>(SB)

TEXT libc_setrlimit_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_setrlimit(SB)

GLOBL	·libc_setrlimit_trampoline_addr(SB), RODATA, $8
DATA	·libc_setrlimit_trampoline_addr(SB)/8, $libc_setrlimit_trampoline<>(SB)

TEXT libc_execve_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_execve(SB)

GLOBL	·libc_execve_trampoline_addr(SB), RODATA, $8
DATA	·libc_execve_trampoline_addr(SB)/8, $libc_execve_trampoline<>(SB)

TEXT libc_exit_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_exit(SB)

GLOBL	·libc_exit_trampoline_addr(SB), RODATA, $8
DATA	·libc_exit_trampoline_addr(SB)/8, $libc_exit_trampoline<>(SB)

TEXT libc_setpgid_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_setpgid(SB)

GLOBL	·libc_setpgid_trampoline_addr(SB), RODATA, $8
DATA	·libc_setpgid_trampoline_addr(SB)/8, $libc_setpgid_trampoline<>(SB)

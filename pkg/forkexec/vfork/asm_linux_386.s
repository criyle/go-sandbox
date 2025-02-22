// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// See ../runtime/sys_linux_386.s for the reason why we always use int 0x80
// instead of the glibc-specific "CALL 0x10(GS)".
#define INVOKE_SYSCALL	INT	$0x80

// func RawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·RawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-24
	MOVL	trap+0(FP), AX	// syscall entry
	MOVL	a1+4(FP), BX
	MOVL	a2+8(FP), CX
	MOVL	a3+12(FP), DX
	POPL	SI // preserve return address
	INVOKE_SYSCALL
	PUSHL	SI
	CMPL	AX, $0xfffff001
	JLS	ok
	MOVL	$-1, r1+16(FP)
	NEGL	AX
	MOVL	AX, err+20(FP)
	RET
ok:
	MOVL	AX, r1+16(FP)
	MOVL	$0, err+20(FP)
	RET

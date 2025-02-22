// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && (mips || mipsle)

#include "textflag.h"

// func RawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·RawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-24
	MOVW	a1+4(FP), R4
	MOVW	a2+8(FP), R5
	MOVW	a3+12(FP), R6
	MOVW	trap+0(FP), R2	// syscall entry
	SYSCALL
	BEQ	R7, ok
	MOVW	$-1, R1
	MOVW	R1, r1+16(FP)	// r1
	MOVW	R2, err+20(FP)	// errno
	RET
ok:
	MOVW	R2, r1+16(FP)	// r1
	MOVW	R0, err+20(FP)	// errno
	RET

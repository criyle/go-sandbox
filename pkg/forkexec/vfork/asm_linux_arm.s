// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func RawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·RawVforkSyscall(SB),NOSPLIT|NOFRAME,$0-24
	MOVW	trap+0(FP), R7	// syscall entry
	MOVW	a1+4(FP), R0
	MOVW	a2+8(FP), R1
	MOVW	a3+12(FP), R2
	SWI	$0
	MOVW	$0xfffff001, R1
	CMP	R1, R0
	BLS	ok
	MOVW	$-1, R1
	MOVW	R1, r1+16(FP)
	RSB	$0, R0, R0
	MOVW	R0, err+20(FP)
	RET
ok:
	MOVW	R0, r1+16(FP)
	MOVW	$0, R0
	MOVW	R0, err+20(FP)
	RET

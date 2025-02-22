// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func RawVforkSyscall(trap, a1, a2, a3 uintptr) (r1, err uintptr)
TEXT ·RawVforkSyscall(SB),NOSPLIT,$0-48
	MOVV	a1+8(FP), R4
	MOVV	a2+16(FP), R5
	MOVV	a3+24(FP), R6
	MOVV	$0, R7
	MOVV	$0, R8
	MOVV	$0, R9
	MOVV	trap+0(FP), R11	// syscall entry
	SYSCALL
	MOVW	$-4096, R12
	BGEU	R12, R4, ok
	MOVV	$-1, R12
	MOVV	R12, r1+32(FP)	// r1
	SUBVU	R4, R0, R4
	MOVV	R4, err+40(FP)	// errno
	RET
ok:
	MOVV	R4, r1+32(FP)	// r1
	MOVV	R0, err+40(FP)	// errno
	RET

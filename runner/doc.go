// Package runner provides common interface for program runner together with
// common types including Result, Limit, Size and Status.
//
// Status
//
// Status defines the program running result status including
//  Normal
//  Program Error
//      Resource Limit Exceeded (Time / Memory / Output)
//      Unauthorized Access (Disallowed Syscall)
//      Runtime Error (Signaled / Nonzero Exit Status)
//  Program Runner Error
//
// Size
//
// Size defines size in bytes, underlying type is uint64 so it
// is effective to store up to EiB of size
//
// Limit
//
// Limit defines Time & Memory restriction on program runner
//
// Result
//
// Result defines program running result including
// Status, ExitStatus, Detailed Error, Time, Memory,
// SetupTime and RunningTime (in real clock)
//
// Runner
//
// General interface to run a program, including a context
// for canclation
package runner

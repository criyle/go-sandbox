// Package forkexec provides interface to run a subprocess with seccomp filter, rlimit and
// containerized or ptraced.
//
// unshare cgroup namespace requires kernel >= 4.6
// seccomp, unshare pid / user namespaces requires kernel >= 3.8
// pipe2, dup3 requires kernel >= 2.6.27
package forkexec

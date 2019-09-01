package filehandler

// SyscallCounter defines a count-down for each each syscall occurs
type SyscallCounter map[string]int

// NewSyscallCounter creates a new SyscallCounter
func NewSyscallCounter() SyscallCounter {
	return SyscallCounter(make(map[string]int))
}

// Add adds single counter to SyscallCounter
func (s SyscallCounter) Add(name string, count int) {
	s[name] = count
}

// AddRange add multiple counter to SyscallCounter
func (s SyscallCounter) AddRange(m map[string]int) {
	for k, v := range m {
		s[k] = v
	}
}

// Check return inside, allow
func (s SyscallCounter) Check(name string) (bool, bool) {
	n, o := s[name]
	if o {
		s[name] = n - 1
		if n <= 1 {
			return true, false
		}
		return true, true
	}
	return false, true
}

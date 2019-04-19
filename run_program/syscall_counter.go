package main

type syscallCounter map[string]int

func newSyscallCounter() syscallCounter {
	return syscallCounter(make(map[string]int))
}

func (s syscallCounter) add(name string, count int) {
	s[name] = count
}

func (s syscallCounter) addRange(m map[string]int) {
	for k, v := range m {
		s[k] = v
	}
}

// check return inside, allow
func (s syscallCounter) check(name string) (bool, bool) {
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

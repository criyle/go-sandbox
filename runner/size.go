package runner

import "fmt"

// Size stores number of byte for the object. E.g. Memory.
// Maximun size is bounded by 64-bit limit
type Size uint64

// String stringer interface for print
func (s Size) String() string {
	t := uint64(s)
	switch {
	case t < 1<<10:
		return fmt.Sprintf("%d B", t)
	case t < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(t)/float64(1<<10))
	case t < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(t)/float64(1<<20))
	default:
		return fmt.Sprintf("%.1f GiB", float64(t)/float64(1<<30))
	}
}

// Byte return size in bytes
func (s Size) Byte() uint64 {
	return uint64(s)
}

// KiB return size in KiB
func (s Size) KiB() uint64 {
	return uint64(s) >> 10
}

// MiB return size in MiB
func (s Size) MiB() uint64 {
	return uint64(s) >> 20
}

// GiB return size in GiB
func (s Size) GiB() uint64 {
	return uint64(s) >> 30
}

// TiB return size in TiB
func (s Size) TiB() uint64 {
	return uint64(s) >> 40
}

// PiB return size in PiB
func (s Size) PiB() uint64 {
	return uint64(s) >> 50
}

// EiB return size in EiB
func (s Size) EiB() uint64 {
	return uint64(s) >> 60
}

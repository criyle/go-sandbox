package mount

// Builder builds fork_exec friendly mount syscall format
type Builder struct {
	Mounts []Mount
}

// NewBuilder creates new mount builder instance
func NewBuilder() *Builder {
	return &Builder{}
}

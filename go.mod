module github.com/criyle/go-sandbox

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-seccomp-bpf v1.1.0
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68
)

replace github.com/elastic/go-seccomp-bpf => ../go-seccomp-bpf

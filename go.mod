module github.com/criyle/go-sandbox

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-seccomp-bpf v1.1.0
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20200904194848-62affa334b73
	golang.org/x/sys v0.0.0-20200905004654-be1d3432aa8f
)

replace github.com/elastic/go-seccomp-bpf => ../go-seccomp-bpf

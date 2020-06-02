module github.com/criyle/go-sandbox

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-seccomp-bpf v1.1.0
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9
	golang.org/x/sys v0.0.0-20200602100848-8d3cce7afc34
)

replace github.com/elastic/go-seccomp-bpf => ../go-seccomp-bpf

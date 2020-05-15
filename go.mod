module github.com/criyle/go-sandbox

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-seccomp-bpf v1.1.0
	golang.org/x/net v0.0.0-20200513185701-a91f0712d120
	golang.org/x/sys v0.0.0-20200515095857-1151b9dac4a9
)

replace github.com/elastic/go-seccomp-bpf => ../go-seccomp-bpf

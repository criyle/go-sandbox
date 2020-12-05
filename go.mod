module github.com/criyle/go-sandbox

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-seccomp-bpf v1.1.0
	github.com/kr/text v0.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.6.1 // indirect
	golang.org/x/net v0.0.0-20201202161906-c7110b5ffcbb
	golang.org/x/sys v0.0.0-20201204225414-ed752295db88
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

replace github.com/elastic/go-seccomp-bpf => ../go-seccomp-bpf

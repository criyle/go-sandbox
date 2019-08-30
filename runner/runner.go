package runner

import "github.com/criyle/go-sandbox/types"

// Runner interface defines method to start running
type Runner interface {
	Start(<-chan struct{}) (<-chan types.Result, error)
}

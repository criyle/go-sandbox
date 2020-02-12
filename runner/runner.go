package runner

import (
	"context"

	"github.com/criyle/go-sandbox/types"
)

// Runner interface defines method to start running
type Runner interface {
	Run(context.Context) <-chan types.Result
}

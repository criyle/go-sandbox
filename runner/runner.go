package runner

import (
	"context"
)

// Runner interface defines method to start running
type Runner interface {
	Run(context.Context) Result
}

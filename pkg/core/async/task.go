package async

import (
	"context"

	"github.com/skygeario/skygear-server/pkg/core/config"
)

type TaskSpec struct {
	Name  string
	Param interface{}
}

type TaskFactory interface {
	NewTask(ctx context.Context, taskCtx TaskContext) Task
}

type Task interface {
	Run(param interface{}) error
}

type TaskContext struct {
	RequestID    string
	TenantConfig config.TenantConfiguration
}

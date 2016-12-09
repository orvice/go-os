package discovery

import (
	"time"

	"github.com/micro/go-micro/client"
	"github.com/micro/go-micro/registry"
)

const (
	HeartbeatTopic = "micro.discovery.heartbeat"
	WatchTopic     = "micro.discovery.watch"
)

// Discovery builds on the registry as a mechanism
// for finding services. It includes heartbeating
// to notify of liveness and caching of the registry.
type Discovery interface {
	Close() error
	registry.Registry
}

type Options struct {
	Registry  registry.Registry
	Client    client.Client
	Interval  time.Duration
	Discovery bool // enable/disable querying discovery versus registry
}

type Option func(*Options)

func NewDiscovery(opts ...Option) Discovery {
	return newOS(opts...)
}

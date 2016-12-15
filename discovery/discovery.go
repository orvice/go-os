// Package discovery is an interface for scalable service discovery.
package discovery

import (
	"github.com/micro/go-micro/registry"
)

const (
	HeartbeatTopic = "micro.discovery.heartbeat"
	WatchTopic     = "micro.discovery.watch"
)

// Discovery builds on the registry for heartbeating and client side caching
type Discovery interface {
	Close() error
	registry.Registry
}

func NewDiscovery(opts ...registry.Option) Discovery {
	return newOS(opts...)
}

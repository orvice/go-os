package discovery

import (
	"sync"
	"time"

	"github.com/micro/go-micro/client"
	"github.com/micro/go-micro/registry"

	proto2 "github.com/micro/discovery-srv/proto/registry"
	proto "github.com/micro/go-os/discovery/proto"
	"golang.org/x/net/context"
)

type os struct {
	exit chan bool
	opts Options

	reg proto2.RegistryClient

	sync.RWMutex
	heartbeats map[string]*proto.Heartbeat
	cache      map[string][]*registry.Service
}

type watcher struct {
	wc proto2.Registry_WatchClient
}

func newOS(opts ...Option) Discovery {
	opt := Options{
		Discovery: true,
	}

	for _, o := range opts {
		o(&opt)
	}

	if opt.Registry == nil {
		opt.Registry = registry.DefaultRegistry
	}

	if opt.Client == nil {
		opt.Client = client.DefaultClient
	}

	if opt.Interval == time.Duration(0) {
		opt.Interval = time.Second * 30
	}

	o := &os{
		exit:       make(chan bool),
		opts:       opt,
		heartbeats: make(map[string]*proto.Heartbeat),
		cache:      make(map[string][]*registry.Service),
		reg:        proto2.NewRegistryClient("go.micro.srv.discovery", opt.Client),
	}

	go o.run()
	return o
}

func values(v []*registry.Value) []*proto.Value {
	if len(v) == 0 {
		return []*proto.Value{}
	}

	var vs []*proto.Value
	for _, vi := range v {
		vs = append(vs, &proto.Value{
			Name:   vi.Name,
			Type:   vi.Type,
			Values: values(vi.Values),
		})
	}
	return vs
}

func toValues(v []*proto.Value) []*registry.Value {
	if len(v) == 0 {
		return []*registry.Value{}
	}

	var vs []*registry.Value
	for _, vi := range v {
		vs = append(vs, &registry.Value{
			Name:   vi.Name,
			Type:   vi.Type,
			Values: toValues(vi.Values),
		})
	}
	return vs
}

func toProto(s *registry.Service) *proto.Service {
	var endpoints []*proto.Endpoint
	for _, ep := range s.Endpoints {
		var request, response *proto.Value

		if ep.Request != nil {
			request = &proto.Value{
				Name:   ep.Request.Name,
				Type:   ep.Request.Type,
				Values: values(ep.Request.Values),
			}
		}

		if ep.Response != nil {
			response = &proto.Value{
				Name:   ep.Response.Name,
				Type:   ep.Response.Type,
				Values: values(ep.Response.Values),
			}
		}

		endpoints = append(endpoints, &proto.Endpoint{
			Name:     ep.Name,
			Request:  request,
			Response: response,
			Metadata: ep.Metadata,
		})
	}

	var nodes []*proto.Node

	for _, node := range s.Nodes {
		nodes = append(nodes, &proto.Node{
			Id:       node.Id,
			Address:  node.Address,
			Port:     int64(node.Port),
			Metadata: node.Metadata,
		})
	}

	return &proto.Service{
		Name:      s.Name,
		Version:   s.Version,
		Metadata:  s.Metadata,
		Endpoints: endpoints,
		Nodes:     nodes,
	}
}

func toService(s *proto.Service) *registry.Service {
	var endpoints []*registry.Endpoint
	for _, ep := range s.Endpoints {
		var request, response *registry.Value

		if ep.Request != nil {
			request = &registry.Value{
				Name:   ep.Request.Name,
				Type:   ep.Request.Type,
				Values: toValues(ep.Request.Values),
			}
		}

		if ep.Response != nil {
			response = &registry.Value{
				Name:   ep.Response.Name,
				Type:   ep.Response.Type,
				Values: toValues(ep.Response.Values),
			}
		}

		endpoints = append(endpoints, &registry.Endpoint{
			Name:     ep.Name,
			Request:  request,
			Response: response,
			Metadata: ep.Metadata,
		})
	}

	var nodes []*registry.Node
	for _, node := range s.Nodes {
		nodes = append(nodes, &registry.Node{
			Id:       node.Id,
			Address:  node.Address,
			Port:     int(node.Port),
			Metadata: node.Metadata,
		})
	}

	return &registry.Service{
		Name:      s.Name,
		Version:   s.Version,
		Metadata:  s.Metadata,
		Endpoints: endpoints,
		Nodes:     nodes,
	}
}

func (w *watcher) Next() (*registry.Result, error) {
	r, err := w.wc.Recv()
	if err != nil {
		return nil, err
	}

	return &registry.Result{
		Action:  r.Result.Action,
		Service: toService(r.Result.Service),
	}, nil
}

func (w *watcher) Stop() {
	w.wc.Close()
}

func (o *os) heartbeat(t *time.Ticker) {
	for _ = range t.C {
		o.RLock()
		for _, hb := range o.heartbeats {
			hb.Timestamp = time.Now().Unix()
			pub := o.opts.Client.NewPublication(HeartbeatTopic, hb)
			o.opts.Client.Publish(context.TODO(), pub)
		}
		o.RUnlock()
	}
}

func (o *os) watch(ch chan *registry.Result) {
	watch, _ := o.Watch()
	defer watch.Stop()

	for {
		next, err := watch.Next()
		if err != nil {
			w, err := o.Watch()
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			watch.Stop()
			watch = w
			time.Sleep(time.Second)
			continue
		}
		ch <- next
	}
}

func (o *os) run() {
	ch := make(chan *registry.Result)
	t := time.NewTicker(o.opts.Interval)

	go o.watch(ch)
	go o.heartbeat(t)

	for {
		select {
		case <-o.exit:
			t.Stop()
			return
		case next, ok := <-ch:
			if !ok {
				return
			}
			o.update(next)
		}
	}
}

func (o *os) update(res *registry.Result) {
	if res == nil || res.Service == nil {
		return
	}

	o.Lock()
	defer o.Unlock()

	services, ok := o.cache[res.Service.Name]
	if !ok {
		// we're not going to cache anything
		// unless there was already a lookup
		return
	}

	if len(res.Service.Nodes) == 0 {
		switch res.Action {
		case "delete":
			delete(o.cache, res.Service.Name)
		}
		return
	}

	// existing service found
	var service *registry.Service
	var index int
	for i, s := range services {
		if s.Version == res.Service.Version {
			service = s
			index = i
		}
	}

	switch res.Action {
	case "create", "update":
		if service == nil {
			services = append(services, res.Service)
			o.cache[res.Service.Name] = services
			return
		}

		// append old nodes to new service
		for _, cur := range service.Nodes {
			var seen bool
			for _, node := range res.Service.Nodes {
				if cur.Id == node.Id {
					seen = true
					break
				}
			}
			if !seen {
				res.Service.Nodes = append(res.Service.Nodes, cur)
			}
		}

		services[index] = res.Service
		o.cache[res.Service.Name] = services
	case "delete":
		if service == nil {
			return
		}

		var nodes []*registry.Node

		// filter cur nodes to remove the dead one
		for _, cur := range service.Nodes {
			var seen bool
			for _, del := range res.Service.Nodes {
				if del.Id == cur.Id {
					seen = true
					break
				}
			}
			if !seen {
				nodes = append(nodes, cur)
			}
		}

		if len(nodes) == 0 {
			if len(services) == 1 {
				delete(o.cache, service.Name)
			} else {
				var srvs []*registry.Service
				for _, s := range services {
					if s.Version != service.Version {
						srvs = append(srvs, s)
					}
				}
				o.cache[service.Name] = srvs
			}
			return
		}

		service.Nodes = nodes
		services[index] = service
		o.cache[res.Service.Name] = services
	}
}

func (o *os) Close() error {
	select {
	case <-o.exit:
		return nil
	default:
		close(o.exit)
	}
	return nil
}

func (o *os) Register(s *registry.Service, opts ...registry.RegisterOption) error {
	o.Lock()
	defer o.Unlock()

	service := toProto(s)

	if _, err := o.reg.Register(context.TODO(), &proto2.RegisterRequest{
		Service: service,
	}); err != nil {
		return err
	}

	hb := &proto.Heartbeat{
		Id:       s.Nodes[0].Id,
		Service:  service,
		Interval: int64(o.opts.Interval.Seconds()),
		Ttl:      int64((o.opts.Interval.Seconds()) * 5),
	}

	o.heartbeats[hb.Id] = hb

	// now register
	return o.opts.Client.Publish(context.TODO(), o.opts.Client.NewPublication(WatchTopic, &proto.Result{
		Action:    "update",
		Service:   service,
		Timestamp: time.Now().Unix(),
	}))
}

func (o *os) Deregister(s *registry.Service) error {
	o.Lock()
	defer o.Unlock()

	service := toProto(s)

	if _, err := o.reg.Deregister(context.TODO(), &proto2.DeregisterRequest{
		Service: service,
	}); err != nil {
		return err
	}

	delete(o.heartbeats, s.Nodes[0].Id)

	// now deregister
	return o.opts.Client.Publish(context.TODO(), o.opts.Client.NewPublication(WatchTopic, &proto.Result{
		Action:    "delete",
		Service:   service,
		Timestamp: time.Now().Unix(),
	}))
}

func (o *os) GetService(name string) ([]*registry.Service, error) {
	o.RLock()
	if services, ok := o.cache[name]; ok {
		o.RUnlock()
		return services, nil
	}
	o.RUnlock()

	rsp, err := o.reg.GetService(context.TODO(), &proto2.GetServiceRequest{Service: name})
	if err != nil {
		return nil, err
	}

	var services []*registry.Service
	for _, service := range rsp.Services {
		services = append(services, toService(service))
	}

	// cache on lookup
	o.Lock()
	o.cache[name] = services
	o.Unlock()
	return services, nil
}

// TODO: prepopulate the cache
func (o *os) ListServices() ([]*registry.Service, error) {
	o.RLock()
	if cache := o.cache; len(cache) > 0 {
		o.RUnlock()
		var services []*registry.Service
		for _, service := range cache {
			services = append(services, service...)
		}
		return services, nil
	}
	o.RUnlock()

	rsp, err := o.reg.ListServices(context.TODO(), &proto2.ListServicesRequest{})
	if err != nil {
		return nil, err
	}

	var services []*registry.Service
	for _, service := range rsp.Services {
		services = append(services, toService(service))
	}
	return services, nil
}

// TODO: subscribe to events rather than the registry itself?
func (o *os) Watch() (registry.Watcher, error) {
	wc, err := o.reg.Watch(context.TODO(), &proto2.WatchRequest{})
	if err != nil {
		return nil, err
	}
	return &watcher{wc}, nil
}

func (o *os) String() string {
	return "os"
}

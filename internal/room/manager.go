package room

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types/container"
	dockerMount "github.com/docker/docker/api/types/mount"
	network "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	dockerClient "github.com/docker/docker/client"
	dockerNames "github.com/docker/docker/daemon/names"
	"github.com/docker/go-connections/nat"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/m1k1o/neko-rooms/internal/config"
	"github.com/m1k1o/neko-rooms/internal/policies"
	"github.com/m1k1o/neko-rooms/internal/types"
	"github.com/m1k1o/neko-rooms/internal/utils"
)

const (
	frontendPort        = 8080
	templateStoragePath = "./templates"
	privateStoragePath  = "./rooms"
	privateStorageUid   = 1000
	privateStorageGid   = 1000
)

func New(client *dockerClient.Client, config *config.Room) *RoomManagerCtx {
	logger := log.With().Str("module", "room").Logger()

	return &RoomManagerCtx{
		logger: logger,
		config: config,
		client: client,
		events: newEvents(config, client),
	}
}

type RoomManagerCtx struct {
	logger zerolog.Logger
	config *config.Room
	client *dockerClient.Client
	events *events
}

func (manager *RoomManagerCtx) Config() types.RoomsConfig {
	return types.RoomsConfig{
		Connections:    manager.config.EprMax - manager.config.EprMin + 1,
		NekoImages:     manager.config.NekoImages,
		StorageEnabled: manager.config.StorageEnabled,
		UsesMux:        manager.config.Mux,
	}
}


func (manager *RoomManagerCtx) Create(ctx context.Context, settings types.RoomSettings) (string, error) {
	if settings.Name != "" && !dockerNames.RestrictedNamePattern.MatchString(settings.Name) {
		return "", fmt.Errorf("invalid container name, must match %s", dockerNames.RestrictedNameChars)
	}

	if in, _ := utils.ArrayIn(settings.NekoImage, manager.config.NekoImages); !in {
		return "", fmt.Errorf("invalid neko image")
	}

	isPrivilegedImage, _ := utils.ArrayIn(settings.NekoImage, manager.config.NekoPrivilegedImages)

	// if api version is not set, try to detect it
	if settings.ApiVersion == 0 {
		inspect, _, err := manager.client.ImageInspectWithRaw(ctx, settings.NekoImage)
		if err != nil {
			return "", err
		}

		// based on image label
		if val, ok := inspect.Config.Labels["m1k1o.neko_rooms.api_version"]; ok {
			var err error
			settings.ApiVersion, err = strconv.Atoi(val)
			if err != nil {
				return "", err
			}
		} else

		// based on opencontainers image url label
		if val, ok := inspect.Config.Labels["org.opencontainers.image.url"]; ok {
			// TODO: this should be removed in future, but since we have a lot of legacy images, we need to support it
			switch val {
			case "https://github.com/m1k1o/neko":
				settings.ApiVersion = 2
			case "https://github.com/demodesk/neko":
				settings.ApiVersion = 3
			}
		}

		// still unable to detect api version
		if settings.ApiVersion == 0 {
			// TODO: this should be removed in future, but since we have a lot of v2 images, we need to support it
			log.Warn().Str("image", settings.NekoImage).Msg("unable to detect api version, fallback to v2")
			settings.ApiVersion = 2
		}
	}

	// TODO: Check if path name exists.
	roomName := settings.Name
	if roomName == "" {
		var err error
		roomName, err = utils.NewUID(8)
		if err != nil {
			return "", err
		}
	}

	containerName := manager.config.InstanceName + "-" + roomName

	//
	// Allocate ports
	//

	portsNeeded := settings.MaxConnections
	if manager.config.Mux {
		portsNeeded = 1
	}

	epr, err := manager.allocatePorts(ctx, portsNeeded)
	if err != nil {
		return "", err
	}

	portBindings := nat.PortMap{}
	for port := epr.Min; port <= epr.Max; port++ {
		portBindings[nat.Port(fmt.Sprintf("%d/udp", port))] = []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: fmt.Sprintf("%d", port),
			},
		}

		// expose TCP port as well when using mux
		if manager.config.Mux {
			portBindings[nat.Port(fmt.Sprintf("%d/tcp", port))] = []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", port),
				},
			}
		}
	}

	exposedPorts := nat.PortSet{
		nat.Port(fmt.Sprintf("%d/tcp", frontendPort)): struct{}{},
		nat.Port("9222/tcp"): struct{}{},  // Add Chrome DevTools Protocol port
	}

	for port := range portBindings {
		exposedPorts[port] = struct{}{}
	}

	// Get container count and calculate debug port
	containerCount, err := manager.getContainerCount(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get container count: %v", err)
	}
	debugPort := 9000 + containerCount

	portBindings[nat.Port("9222/tcp")] = []nat.PortBinding{
		{
			HostIP:   "0.0.0.0",
			HostPort: fmt.Sprintf("%d", debugPort),
		},
	}
	
	//
	// Set internal labels
	//

	var browserPolicyLabels *BrowserPolicyLabels
	if settings.BrowserPolicy != nil {
		browserPolicyLabels = &BrowserPolicyLabels{
			Type: settings.BrowserPolicy.Type,
			Path: settings.BrowserPolicy.Path,
		}
	}

	labels := manager.serializeLabels(RoomLabels{
		Name: roomName,
		Mux:  manager.config.Mux,
		Epr:  epr,

		NekoImage:  settings.NekoImage,
		ApiVersion: settings.ApiVersion,

		BrowserPolicy: browserPolicyLabels,
		UserDefined:   settings.Labels,
	})

	//
	// Set traefik labels
	//

	pathPrefix := path.Join("/", manager.config.PathPrefix, roomName)

	if t := manager.config.Traefik; t.Enabled {
		// create traefik rule
		traefikRule := "PathPrefix(`" + pathPrefix + "`)"
		if t.Domain != "" && t.Domain != "*" {
			// match *.domain.tld as subdomain
			if strings.HasPrefix(t.Domain, "*.") {
				traefikRule = fmt.Sprintf(
					"Host(`%s.%s`)",
					roomName,
					strings.TrimPrefix(t.Domain, "*."),
				)
			} else {
				traefikRule += " && Host(`" + t.Domain + "`)"
			}
		} else {
			traefikRule += " && HostRegexp(`{host:.+}`)"
		}

		labels["traefik.enable"] = "true"
		labels["traefik.http.services."+containerName+"-frontend.loadbalancer.server.port"] = fmt.Sprintf("%d", frontendPort)
		labels["traefik.http.routers."+containerName+".entrypoints"] = t.Entrypoint
		labels["traefik.http.routers."+containerName+".rule"] = traefikRule
		labels["traefik.http.middlewares."+containerName+"-rdr.redirectregex.regex"] = pathPrefix + "$$"
		labels["traefik.http.middlewares."+containerName+"-rdr.redirectregex.replacement"] = pathPrefix + "/"
		labels["traefik.http.middlewares."+containerName+"-prf.stripprefix.prefixes"] = pathPrefix + "/"
		labels["traefik.http.routers."+containerName+".middlewares"] = containerName + "-rdr," + containerName + "-prf"
		labels["traefik.http.routers."+containerName+".service"] = containerName + "-frontend"

		// optional HTTPS
		if t.Certresolver != "" {
			labels["traefik.http.routers."+containerName+".tls"] = "true"
			labels["traefik.http.routers."+containerName+".tls.certresolver"] = t.Certresolver
		}
	} else {
		labels["m1k1o.neko_rooms.proxy.enabled"] = "true"
		labels["m1k1o.neko_rooms.proxy.path"] = pathPrefix
		labels["m1k1o.neko_rooms.proxy.port"] = fmt.Sprintf("%d", frontendPort)
	}

	// add custom labels
	for _, label := range manager.config.Labels {
		// replace dynamic values in labels
		label = strings.Replace(label, "{containerName}", containerName, -1)
		label = strings.Replace(label, "{roomName}", roomName, -1)

		if t := manager.config.Traefik; t.Enabled {
			label = strings.Replace(label, "{traefikEntrypoint}", t.Entrypoint, -1)
			label = strings.Replace(label, "{traefikCertresolver}", t.Certresolver, -1)
		}

		v := strings.SplitN(label, "=", 2)
		if len(v) != 2 {
			manager.logger.Warn().Str("label", label).Msg("invalid custom label")
			continue
		}

		key, val := v[0], v[1]
		labels[key] = val
	}

	//
	// Set environment variables
	//

	env, err := settings.ToEnv(
		manager.config,
		types.PortSettings{
			FrontendPort: frontendPort,
			EprMin:       epr.Min,
			EprMax:       epr.Max,
		})
	if err != nil {
		return "", err
	}

	//
	// Set browser policies
	//

	if settings.BrowserPolicy != nil {
		if !manager.config.StorageEnabled {
			return "", fmt.Errorf("policies cannot be specified, because storage is disabled or unavailable")
		}

		policyJson, err := policies.Generate(settings.BrowserPolicy.Content, settings.BrowserPolicy.Type)
		if err != nil {
			return "", err
		}

		// create policy path (+ also get host path)
		policyPath := fmt.Sprintf("/%s-%s-policy.json", roomName, settings.BrowserPolicy.Type)
		templateInternalPath := path.Join(manager.config.StorageInternal, templateStoragePath)
		policyInternalPath := path.Join(templateInternalPath, policyPath)

		// create dir if does not exist
		if _, err := os.Stat(templateInternalPath); os.IsNotExist(err) {
			if err := os.MkdirAll(templateInternalPath, os.ModePerm); err != nil {
				return "", err
			}
		}

		// write policy to file
		if err := os.WriteFile(policyInternalPath, []byte(policyJson), 0644); err != nil {
			return "", err
		}

		// mount policy file
		settings.Mounts = append(settings.Mounts, types.RoomMount{
			Type:          types.MountTemplate,
			HostPath:      policyPath,
			ContainerPath: settings.BrowserPolicy.Path,
		})
	}

	//
	// Set container mounts
	//

	paths := map[string]bool{}
	mounts := []dockerMount.Mount{}
	for _, mount := range settings.Mounts {
		// ignore duplicates
		if _, ok := paths[mount.ContainerPath]; ok {
			continue
		}

		readOnly := false

		hostPath := filepath.Clean(mount.HostPath)
		containerPath := filepath.Clean(mount.ContainerPath)

		if !filepath.IsAbs(hostPath) || !filepath.IsAbs(containerPath) {
			return "", fmt.Errorf("mount paths must be absolute")
		}

		switch mount.Type {
		case types.MountPrivate:
			if !manager.config.StorageEnabled {
				return "", fmt.Errorf("private mounts cannot be specified, because storage is disabled or unavailable")
			}

			// ensure that target exists with correct permissions
			internalPath := path.Join(manager.config.StorageInternal, privateStoragePath, roomName, hostPath)
			if _, err := os.Stat(internalPath); os.IsNotExist(err) {
				if err := os.MkdirAll(internalPath, os.ModePerm); err != nil {
					return "", err
				}

				if err := utils.ChownR(internalPath, privateStorageUid, privateStorageGid); err != nil {
					return "", err
				}
			}

			// prefix host path
			hostPath = path.Join(manager.config.StorageExternal, privateStoragePath, roomName, hostPath)
		case types.MountTemplate:
			if !manager.config.StorageEnabled {
				return "", fmt.Errorf("template mounts cannot be specified, because storage is disabled or unavailable")
			}

			// readonly template data
			readOnly = true

			// prefix host path
			hostPath = path.Join(manager.config.StorageExternal, templateStoragePath, hostPath)
		case types.MountProtected, types.MountPublic:
			// readonly if mount type is protected
			readOnly = mount.Type == types.MountProtected

			// public whitelisted mounts
			var isAllowed = false
			for _, path := range manager.config.MountsWhitelist {
				if strings.HasPrefix(hostPath, path) {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				return "", fmt.Errorf("mount path is not whitelisted in config")
			}
		default:
			return "", fmt.Errorf("unknown mount type %q", mount.Type)
		}

		mounts = append(mounts,
			dockerMount.Mount{
				Type:        dockerMount.TypeBind,
				Source:      hostPath,
				Target:      containerPath,
				ReadOnly:    readOnly,
				Consistency: dockerMount.ConsistencyDefault,

				BindOptions: &dockerMount.BindOptions{
					Propagation:  dockerMount.PropagationRPrivate,
					NonRecursive: false,
				},
			},
		)

		paths[mount.ContainerPath] = true
	}

	//
	// Set container device requests
	//

	var deviceRequests []container.DeviceRequest

	if len(settings.Resources.Gpus) > 0 {
		gpuOpts := opts.GpuOpts{}

		// convert to csv
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		if err := w.Write(settings.Resources.Gpus); err != nil {
			return "", err
		}
		w.Flush()

		// set GPU opts
		if err := gpuOpts.Set(buf.String()); err != nil {
			return "", err
		}

		deviceRequests = append(deviceRequests, gpuOpts.Value()...)
	}

	//
	// Set container devices
	//

	var devices []container.DeviceMapping
	for _, device := range settings.Resources.Devices {
		devices = append(devices, container.DeviceMapping{
			PathOnHost:        device,
			PathInContainer:   device,
			CgroupPermissions: "rwm",
		})
	}

	//
	// Set container configs
	//

	hostname := containerName
	if settings.Hostname != "" {
		hostname = settings.Hostname
	}

	config := &container.Config{
		// Hostname
		Hostname: hostname,
		// Domainname is preventing from running container on LXC (Proxmox)
		// https://www.gitmemory.com/issue/docker/for-linux/743/524569376
		// Domainname: containerName,
		// List of exposed ports
		ExposedPorts: exposedPorts,
		// List of environment variable to set in the container
		Env: env,
		// Name of the image as it was passed by the operator (e.g. could be symbolic)
		Image: settings.NekoImage,
		// List of labels set to this container
		Labels: labels,
	}

	hostConfig := &container.HostConfig{
		// Port mapping between the exposed port (container) and the host
		PortBindings: portBindings,
		// Configuration of the logs for this container
		LogConfig: container.LogConfig{
			Type:   "json-file",
			Config: map[string]string{},
		},
		// Restart policy to be used for the container
		RestartPolicy: container.RestartPolicy{
			Name: "unless-stopped",
		},
		// List of kernel capabilities to add to the container
		CapAdd: strslice.StrSlice{
			"SYS_ADMIN",
		},
		// Total shm memory usage
		ShmSize: settings.Resources.ShmSize,
		// Mounts specs used by the container
		Mounts: mounts,
		// Resources contains container's resources (cgroups config, ulimits...)
		Resources: container.Resources{
			CPUShares:      settings.Resources.CPUShares,
			NanoCPUs:       settings.Resources.NanoCPUs,
			Memory:         settings.Resources.Memory,
			DeviceRequests: deviceRequests,
			Devices:        devices,
		},
		// DNS
		DNS: settings.DNS,
		// Privileged
		Privileged: isPrivilegedImage,
	}

	networkingConfig := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			manager.config.InstanceNetwork: {},
		},
	}

	// Creating the actual container
	container, err := manager.client.ContainerCreate(
		ctx,
		config,
		hostConfig,
		networkingConfig,
		nil,
		containerName,
	)

	if err != nil {
		return "", err
	}

	return container.ID[:12], nil
}

func (manager *RoomManagerCtx) GetEntry(ctx context.Context, id string) (*types.RoomEntry, error) {
	// we don't support id shorter than 12 chars
	// because they can be ambiguous
	if len(id) < 12 {
		return nil, types.ErrRoomNotFound
	}

	container, err := manager.containerById(ctx, id)
	if err != nil {
		return nil, err
	}

	return manager.containerToEntry(*container)
}

func (manager *RoomManagerCtx) GetEntryByName(ctx context.Context, name string) (*types.RoomEntry, error) {
	container, err := manager.containerByName(ctx, name)
	if err != nil {
		return nil, err
	}

	return manager.containerToEntry(*container)
}

// events

func (manager *RoomManagerCtx) EventsLoopStart() {
	manager.events.Start()
}

func (manager *RoomManagerCtx) EventsLoopStop() error {
	return manager.events.Shutdown()
}

func (manager *RoomManagerCtx) Events(ctx context.Context) (<-chan types.RoomEvent, <-chan error) {
	return manager.events.Events(ctx)
}

package room

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/m1k1o/neko-rooms/internal/policies"
	"github.com/m1k1o/neko-rooms/internal/types"
)

func (manager *RoomManagerCtx) GetSettings(ctx context.Context, id string) (*types.RoomSettings, error) {
	container, err := manager.inspectContainer(ctx, id)
	if err != nil {
		return nil, err
	}

	labels, err := manager.extractLabels(container.Config.Labels)
	if err != nil {
		return nil, err
	}

	privateStorageRoot := path.Join(manager.config.StorageExternal, privateStoragePath, labels.Name)
	templateStorageRoot := path.Join(manager.config.StorageExternal, templateStoragePath)

	mounts := []types.RoomMount{}
	for _, mount := range container.Mounts {
		mountType := types.MountPublic
		hostPath := mount.Source

		if strings.HasPrefix(hostPath, privateStorageRoot) {
			mountType = types.MountPrivate
			hostPath = strings.TrimPrefix(hostPath, privateStorageRoot)
		} else if strings.HasPrefix(hostPath, templateStorageRoot) {
			mountType = types.MountTemplate
			hostPath = strings.TrimPrefix(hostPath, templateStorageRoot)
		} else if !mount.RW {
			mountType = types.MountProtected
		}

		mounts = append(mounts, types.RoomMount{
			Type:          mountType,
			HostPath:      hostPath,
			ContainerPath: mount.Destination,
		})
	}

	var browserPolicy *types.BrowserPolicy
	if labels.BrowserPolicy != nil {
		browserPolicy = &types.BrowserPolicy{
			Type: labels.BrowserPolicy.Type,
			Path: labels.BrowserPolicy.Path,
		}

		var policyMount *types.RoomMount
		for _, mount := range mounts {
			if mount.ContainerPath == labels.BrowserPolicy.Path {
				policyMount = &mount
				break
			}
		}

		// TODO: Refactor.
		if policyMount != nil && policyMount.Type == types.MountTemplate {
			templateInternalPath := path.Join(manager.config.StorageInternal, templateStoragePath, policyMount.HostPath)
			if _, err := os.Stat(templateInternalPath); !os.IsNotExist(err) {
				if data, err := os.ReadFile(templateInternalPath); err == nil {
					if content, err := policies.Parse(string(data), labels.BrowserPolicy.Type); err == nil {
						browserPolicy.Content = *content
					}
				}
			}
		}
	}

	var roomResources types.RoomResources
	if container.HostConfig != nil {
		gpus := []string{}
		for _, req := range container.HostConfig.DeviceRequests {
			var isGpu bool
			var caps []string
			for _, cc := range req.Capabilities {
				for _, c := range cc {
					if c == "gpu" {
						isGpu = true
						continue
					}
					caps = append(caps, c)
				}
			}
			if !isGpu {
				continue
			}

			if req.Count > 1 {
				gpus = append(gpus, fmt.Sprintf("count=%d", req.Count))
			} else if req.Count == -1 {
				gpus = append(gpus, "all")
			}
			if req.Driver != "" {
				gpus = append(gpus, fmt.Sprintf("driver=%s", req.Driver))
			}
			if len(req.DeviceIDs) > 0 {
				gpus = append(gpus, fmt.Sprintf("device=%s", strings.Join(req.DeviceIDs, ",")))
			}
			if len(caps) > 0 {
				gpus = append(gpus, fmt.Sprintf("capabilities=%s", strings.Join(caps, ",")))
			}
			var opts []string
			for key, val := range req.Options {
				opts = append(opts, fmt.Sprintf("%s=%s", key, val))
			}
			if len(opts) > 0 {
				gpus = append(gpus, fmt.Sprintf("options=%s", strings.Join(opts, ",")))
			}
		}

		devices := []string{}
		for _, dev := range container.HostConfig.Devices {
			// TODO: dev.CgroupPermissions
			if dev.PathOnHost == dev.PathInContainer {
				devices = append(devices, dev.PathOnHost)
			} else {
				devices = append(devices, fmt.Sprintf("%s:%s", dev.PathOnHost, dev.PathInContainer))
			}
		}

		roomResources = types.RoomResources{
			CPUShares: container.HostConfig.CPUShares,
			NanoCPUs:  container.HostConfig.NanoCPUs,
			ShmSize:   container.HostConfig.ShmSize,
			Memory:    container.HostConfig.Memory,
			Gpus:      gpus,
			Devices:   devices,
		}
	}

	settings := types.RoomSettings{
		ApiVersion:     labels.ApiVersion,
		Name:           labels.Name,
		NekoImage:      labels.NekoImage,
		MaxConnections: labels.Epr.Max - labels.Epr.Min + 1,
		Labels:         labels.UserDefined,
		Mounts:         mounts,
		Resources:      roomResources,
		Hostname:       container.Config.Hostname,
		DNS:            container.HostConfig.DNS,
		BrowserPolicy:  browserPolicy,
	}

	if labels.Mux {
		settings.MaxConnections = 0
	}

	err = settings.FromEnv(labels.ApiVersion, container.Config.Env)
	return &settings, err
}
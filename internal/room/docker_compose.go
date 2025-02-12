package room

import (
	"context"
	"fmt"
	"strings"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/m1k1o/neko-rooms/internal/types"
	"gopkg.in/yaml.v3"
)

func (manager *RoomManagerCtx) ExportAsDockerCompose(ctx context.Context) ([]byte, error) {
	services := map[string]any{}

	dockerCompose := map[string]any{
		"version": "3.8",
		"networks": map[string]any{
			"default": map[string]any{
				"name":     manager.config.InstanceNetwork,
				"external": true,
			},
		},
		"services": services,
	}

	containers, err := manager.listContainers(ctx, nil)
	if err != nil {
		return nil, err
	}

	for _, container := range containers {
		containerJson, err := manager.inspectContainer(ctx, container.ID)
		if err != nil {
			return nil, err
		}

		labels, err := manager.extractLabels(containerJson.Config.Labels)
		if err != nil {
			return nil, err
		}

		containerName := containerJson.Name
		containerName = strings.TrimPrefix(containerName, "/")

		service := map[string]any{}
		services[containerName] = service

		service["image"] = labels.NekoImage
		service["container_name"] = containerName
		service["hostname"] = containerJson.Config.Hostname
		service["restart"] = containerJson.HostConfig.RestartPolicy.Name

		// privileged
		if containerJson.HostConfig.Privileged {
			service["privileged"] = true
		}

		// total shm memory usage
		service["shm_size"] = containerJson.HostConfig.ShmSize

		// capabilites
		capAdd := []string{}
		for _, cap := range containerJson.HostConfig.CapAdd {
			capAdd = append(capAdd, string(cap))
		}
		if len(capAdd) > 0 {
			service["cap_add"] = capAdd
		}

		// resources
		resources := map[string]any{}
		{
			limits := map[string]string{}
			// TODO: CPUShares
			if containerJson.HostConfig.NanoCPUs > 0 {
				limits["cpus"] = fmt.Sprintf("%f", float64(containerJson.HostConfig.NanoCPUs)/1000000000)
			}
			if containerJson.HostConfig.Memory > 0 {
				limits["memory"] = fmt.Sprintf("%dM", containerJson.HostConfig.Memory/1024/1024)
			}
			if len(limits) > 0 {
				resources["limits"] = limits
			}

			deviceRequests := []any{}
			for _, device := range containerJson.HostConfig.DeviceRequests {
				deviceRequests = append(deviceRequests, map[string]any{
					"driver":       device.Driver,
					"count":        device.Count,
					"capabilities": device.Capabilities,
				})
			}
			if len(deviceRequests) > 0 {
				resources["reservations"] = map[string]any{
					"devices": deviceRequests,
				}
			}
		}
		if len(resources) > 0 {
			service["deploy"] = map[string]any{
				"resources": resources,
			}
		}

		// hostname
		if containerJson.Config.Hostname != containerName {
			service["hostname"] = containerJson.Config.Hostname
		}

		// dns
		if len(containerJson.HostConfig.DNS) > 0 {
			service["dns"] = containerJson.HostConfig.DNS
		}

		// ports
		ports := []string{}
		for port, host := range containerJson.HostConfig.PortBindings {
			for _, binding := range host {
				ports = append(ports, fmt.Sprintf("%s:%s", binding.HostPort, port))
			}
		}
		if len(ports) > 0 {
			service["ports"] = ports
		}

		// environment variables
		if len(containerJson.Config.Env) > 0 {
			service["environment"] = containerJson.Config.Env
		}

		// volumes
		volumes := []string{}
		for _, mount := range container.Mounts {
			if !mount.RW {
				volumes = append(volumes, fmt.Sprintf("%s:%s:ro", mount.Source, mount.Destination))
			} else {
				volumes = append(volumes, fmt.Sprintf("%s:%s", mount.Source, mount.Destination))
			}
		}
		if len(volumes) > 0 {
			service["volumes"] = volumes
		}

		// devices
		devices := []string{}
		for _, device := range containerJson.HostConfig.Devices {
			devices = append(devices, fmt.Sprintf("%s:%s:%s", device.PathOnHost, device.PathInContainer, device.CgroupPermissions))
		}
		if len(devices) > 0 {
			service["devices"] = devices
		}

		// labels
		labelsArr := []string{}
		for key, val := range containerJson.Config.Labels {
			labelsArr = append(labelsArr, fmt.Sprintf("%s=%s", key, val))
		}
		if len(labelsArr) > 0 {
			service["labels"] = labelsArr
		}
	}

	return yaml.Marshal(dockerCompose)
}


func (manager *RoomManagerCtx) Remove(ctx context.Context, id string) error {
	_, err := manager.inspectContainer(ctx, id)
	if err != nil {
		return err
	}

	// Stop the actual container
	err = manager.client.ContainerStop(ctx, id, container.StopOptions{
		Signal:  "SIGTERM",
		Timeout: &manager.config.StopTimeoutSec,
	})

	if err != nil {
		return err
	}

	// Remove the actual container
	err = manager.client.ContainerRemove(ctx, id, dockerTypes.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})

	return err
}


func (manager *RoomManagerCtx) Start(ctx context.Context, id string) error {
	_, err := manager.inspectContainer(ctx, id)
	if err != nil {
		return err
	}

	// Start the actual container
	return manager.client.ContainerStart(ctx, id, dockerTypes.ContainerStartOptions{})
}

func (manager *RoomManagerCtx) Stop(ctx context.Context, id string) error {
	_, err := manager.inspectContainer(ctx, id)
	if err != nil {
		return err
	}

	// Stop the actual container
	return manager.client.ContainerStop(ctx, id, container.StopOptions{
		Signal:  "SIGTERM",
		Timeout: &manager.config.StopTimeoutSec,
	})
}

func (manager *RoomManagerCtx) Restart(ctx context.Context, id string) error {
	_, err := manager.inspectContainer(ctx, id)
	if err != nil {
		return err
	}

	// Restart the actual container
	return manager.client.ContainerRestart(ctx, id, container.StopOptions{
		Signal:  "SIGTERM",
		Timeout: &manager.config.StopTimeoutSec,
	})
}


func (manager *RoomManagerCtx) List(ctx context.Context, labels map[string]string) ([]types.RoomEntry, error) {
	containers, err := manager.listContainers(ctx, labels)
	if err != nil {
		return nil, err
	}

	result := make([]types.RoomEntry, 0, len(containers))
	for _, container := range containers {
		entry, err := manager.containerToEntry(container)
		if err != nil {
			return nil, err
		}

		result = append(result, *entry)
	}

	return result, nil
}
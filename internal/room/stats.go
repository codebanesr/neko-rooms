package room

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/m1k1o/neko-rooms/internal/types"
)

func (manager *RoomManagerCtx) GetStats(ctx context.Context, id string) (*types.RoomStats, error) {
	container, err := manager.inspectContainer(ctx, id)
	if err != nil {
		return nil, err
	}

	labels, err := manager.extractLabels(container.Config.Labels)
	if err != nil {
		return nil, err
	}

	settings := types.RoomSettings{}
	err = settings.FromEnv(labels.ApiVersion, container.Config.Env)
	if err != nil {
		return nil, err
	}

	var stats types.RoomStats
	switch labels.ApiVersion {
	case 2:
		output, err := manager.containerExec(ctx, id, []string{
			"wget", "-q", "-O-", "http://127.0.0.1:8080/stats?pwd=" + url.QueryEscape(settings.AdminPass),
		})
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(output), &stats); err != nil {
			return nil, err
		}
	case 3:
		output, err := manager.containerExec(ctx, id, []string{
			"wget", "-q", "-O-", "http://127.0.0.1:8080/api/sessions?token=" + url.QueryEscape(settings.AdminPass),
		})
		if err != nil {
			return nil, err
		}

		var sessions []struct {
			ID      string `json:"id"`
			Profile struct {
				Name    string `json:"name"`
				IsAdmin bool   `json:"is_admin"`
			} `json:"profile"`
			State struct {
				IsConnected       bool       `json:"is_connected"`
				NotConnectedSince *time.Time `json:"not_connected_since"`
			} `json:"state"`
		}

		if err := json.Unmarshal([]byte(output), &sessions); err != nil {
			return nil, err
		}

		// create empty array so that it's not null in json
		stats.Members = []*types.RoomMember{}

		for _, session := range sessions {
			if session.State.IsConnected {
				stats.Connections++
				// append members
				stats.Members = append(stats.Members, &types.RoomMember{
					ID:    session.ID,
					Name:  session.Profile.Name,
					Admin: session.Profile.IsAdmin,
					Muted: false, // not supported
				})
			} else if session.State.NotConnectedSince != nil {
				// populate last admin left time
				if session.Profile.IsAdmin && (stats.LastAdminLeftAt == nil || (*session.State.NotConnectedSince).After(*stats.LastAdminLeftAt)) {
					stats.LastAdminLeftAt = session.State.NotConnectedSince
				}
				// populate last user left time
				if !session.Profile.IsAdmin && (stats.LastUserLeftAt == nil || (*session.State.NotConnectedSince).After(*stats.LastUserLeftAt)) {
					stats.LastUserLeftAt = session.State.NotConnectedSince
				}
			}
		}

		// parse started time
		if container.State.StartedAt != "" {
			stats.ServerStartedAt, err = time.Parse(time.RFC3339, container.State.StartedAt)
			if err != nil {
				return nil, err
			}
		}

		// TODO: settings & host
	default:
		return nil, fmt.Errorf("unsupported API version: %d", labels.ApiVersion)
	}

	return &stats, nil
}

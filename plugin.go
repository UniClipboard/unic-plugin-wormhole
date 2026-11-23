// Package wormholeplugin implements an explicit temporary-share Action.
package wormholeplugin

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/UniClipboard/unic-plugin-wormhole/internal/wormhole"
	"github.com/uniclipboard/unic/plugin"
)

const ID = "unic.wormhole"
const Version = "0.1.0"

// Plugin owns provider requests. The host owns content and result history.
type Plugin struct{ client *wormhole.Client }

// New accepts a provider client for process-level acceptance; nil uses production.
func New(client *wormhole.Client) *Plugin {
	if client == nil {
		client = wormhole.New(nil)
	}
	return &Plugin{client: client}
}
func (*Plugin) Spec() plugin.Spec {
	return plugin.Spec{
		ID: ID, Version: Version, APIVersion: 1,
		Capabilities: []string{plugin.CapAction},
		Actions: []plugin.ActionSpec{{
			ID: "share", Title: "通过 Wormhole 临时分享",
			Accepts: []string{"text", "image", "files"},
			Placements: []string{
				plugin.ActionPlacementHistoryItemMenu,
				plugin.ActionPlacementHistoryToolbar,
				plugin.ActionPlacementQuickPanel,
			},
			PostActions: []string{plugin.ActionPostCopy, plugin.ActionPostPresent},
			TimeoutMS:   300000,
		}},
	}
}
func (*Plugin) Init(_ context.Context, _ plugin.Host, config plugin.Config) error {
	if len(config) != 0 {
		return plugin.ErrInvalidConfig
	}
	return nil
}
func (*Plugin) Start(context.Context) error { return nil }
func (*Plugin) Close(context.Context) error { return nil }

func (p *Plugin) Run(ctx context.Context, ac plugin.ActionContext) error {
	if ac.Action() != "share" {
		return plugin.ErrInvalidArgument
	}
	item := ac.Item()
	var files []wormhole.File
	switch item.Type {
	case "text":
		text := item.Text
		if text == "" {
			return plugin.ErrInvalidArgument
		}
		files = []wormhole.File{{
			Name: "clipboard.txt", Size: int64(len(text)),
			Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(text)), nil
			},
		}}
	case "image", "files":
		source, ok := ac.(plugin.ActionSource)
		if !ok {
			return errors.New("wormhole: host does not provide Action content")
		}
		for i, part := range source.Parts() {
			name := part.Name
			if item.Type == "files" {
				if !part.File {
					continue
				}
			} else {
				if part.File {
					continue
				}
				switch part.MIME {
				case "image/png":
					name = "clipboard.png"
				case "image/jpeg":
					name = "clipboard.jpg"
				case "image/gif":
					name = "clipboard.gif"
				case "image/webp":
					name = "clipboard.webp"
				default:
					continue
				}
				if len(files) > 0 {
					continue
				} // Alternative image representations describe the same image.
			}
			files = append(files, wormhole.File{
				Name: name, Size: part.Size,
				Open: func(readerCtx context.Context) (io.ReadCloser, error) {
					return source.OpenPart(readerCtx, i)
				},
			})
		}
	default:
		return plugin.ErrInvalidArgument
	}
	if len(files) == 0 {
		return plugin.ErrInvalidArgument
	}
	url, err := p.client.Share(ctx, files)
	if err != nil {
		return err
	}
	return ac.SetText(url)
}

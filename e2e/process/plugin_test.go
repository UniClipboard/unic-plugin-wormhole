package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	share "github.com/UniClipboard/unic-plugin-wormhole"
	"github.com/UniClipboard/unic-plugin-wormhole/internal/wormhole"
	"github.com/uniclipboard/unic/engine"
	"github.com/uniclipboard/unic/plugin"
)

func TestMain(m *testing.M) {
	if os.Getenv("UNIC_WORMHOLE_HELPER") == "1" {
		var transport http.RoundTripper
		if endpoint := os.Getenv("UNIC_WORMHOLE_FIXTURE"); endpoint != "" {
			transport = fixtureTransport{endpoint: endpoint}
		}
		if err := plugin.Serve(share.New(wormhole.New(transport))); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type fingerprint struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type downloadReceipt struct {
	Lifetime int                    `json:"lifetime"`
	Files    map[string]fingerprint `json:"files"`
}

type payload struct {
	name string
	data []byte
}

func TestPluginProcessE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	live := os.Getenv("UNIC_WORMHOLE_LIVE") == "1"
	var fixture *providerFixture
	if !live {
		fixture = newProviderFixture(t)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(binary)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"UNIC_WORMHOLE_HELPER=1"}
	if fixture != nil {
		env = append(env, "UNIC_WORMHOLE_FIXTURE="+fixture.server.URL)
	}
	e, err := engine.New(ctx, engine.Options{DataDir: dir, Plugins: []engine.PluginInstance{{Process: &engine.PluginProcess{
		Path: exe, SHA256: hex.EncodeToString(checksum[:]), Spec: share.New(nil).Spec(), Args: []string{"-test.run=^$"}, Env: env,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	actions, err := e.ListActions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const actionKey = "unic.wormhole/share"
	found := false
	for _, action := range actions {
		found = found || action.Key == actionKey
	}
	if !found {
		t.Fatal("Wormhole Action was not discovered")
	}
	var pixel bytes.Buffer
	if err := png.Encode(&pixel, image.NewGray(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	text := payload{"clipboard.txt", []byte("Synthetic Wormhole 文本")}
	png := payload{"clipboard.png", pixel.Bytes()}
	files := []payload{
		{"前缀.bin", bytes.Repeat([]byte{11}, 65536-17)},
		{"跨分片.bin", bytes.Repeat([]byte{1, 2, 3, 4}, 1_500_000)},
		{"empty.txt", nil},
	}
	fileInput := engine.ContentInput{}
	for _, file := range files {
		fileInput.Files = append(fileInput.Files, engine.FileInput{Name: file.name, Reader: bytes.NewReader(file.data), Size: int64(len(file.data))})
	}
	tests := []struct {
		name  string
		input engine.ContentInput
		want  []payload
	}{
		{"text", representation(engine.MimeText, text), []payload{text}},
		{"image", representation("image/png", png), []payload{png}},
		{"files", fileInput, files},
	}
	verified := map[string]downloadReceipt{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := e.ImportContent(ctx, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			defer e.ReleaseContent(ctx, h.LeaseID)
			src, err := e.CommitContent(ctx, engine.CommitRequest{RequestID: engine.RequestID("source-" + tc.name), LeaseID: h.LeaseID})
			if err != nil {
				t.Fatal(err)
			}
			req := engine.RunActionRequest{RequestID: engine.RequestID("share-" + tc.name), Key: actionKey, HistoryID: src.HistoryID}
			result, err := e.RunAction(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			again, err := e.RunAction(ctx, req)
			if err != nil || again.HistoryID != result.HistoryID {
				t.Fatal("duplicate request changed result")
			}
			item, err := e.GetItem(ctx, result.HistoryID)
			if err != nil || item.Origin.PluginID != "unic.wormhole" {
				t.Fatal("invalid result origin", err)
			}
			lease, err := e.RetainHistoryContent(ctx, result.HistoryID)
			if err != nil {
				t.Fatal(err)
			}
			defer e.ReleaseContent(ctx, lease.LeaseID)
			reader, err := e.ReadContent(ctx, lease.LeaseID, lease.Content.Parts[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			link, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || !bytes.HasPrefix(link, []byte("https://wormhole.app/")) {
				t.Fatal("invalid result link", err)
			}
			var downloaded downloadReceipt
			if fixture != nil {
				downloaded = fixture.download(t, string(link))
			} else {
				cmd := exec.CommandContext(ctx, "node", "verify-download.mjs")
				cmd.Stdin = bytes.NewReader(link)
				output, err := cmd.Output()
				if err != nil {
					if exit, ok := err.(*exec.ExitError); ok {
						t.Log(strings.TrimSpace(string(exit.Stderr)))
					}
					t.Fatal("independent download failed", err)
				}
				if err := json.Unmarshal(output, &downloaded); err != nil {
					t.Fatal("invalid recipient receipt")
				}
			}
			if downloaded.Lifetime != 86400 || !reflect.DeepEqual(downloaded.Files, fingerprints(tc.want)) {
				t.Fatalf("recipient size, hash, filename or expiration mismatch: %+v", downloaded)
			}
			if _, err := e.GetItem(ctx, src.HistoryID); err != nil {
				t.Fatal("source missing after Action", err)
			}
			verified[tc.name] = downloaded

			if fixture != nil {
				stages := []string{"malformed-room", "malformed-authorization", "upload", "finish"}
				if tc.name == "files" {
					stages = append(stages, "partial-upload")
				}
				for _, stage := range stages {
					fixture.fail.Store(stage)
					request := engine.RunActionRequest{RequestID: engine.RequestID("failure-" + tc.name + "-" + stage), Key: actionKey, HistoryID: src.HistoryID}
					failed, err := e.RunAction(ctx, request)
					if err == nil || failed.HistoryID != "" {
						t.Fatalf("%s created success", stage)
					}
				}
				fixture.fail.Store("")
			}
		})
	}
	if t.Failed() {
		return
	}
	if fixture != nil && fixture.completions.Load() != int32(len(tests)) {
		t.Fatal("provider completed an unexpected number of shares")
	}
	if dir := os.Getenv("UNIC_WORMHOLE_RECEIPTS"); dir != "" {
		mode := "fixture"
		replay := "sh scripts/verify.sh"
		if live {
			mode = "live"
			replay = "UNIC_WORMHOLE_LIVE=1 " + replay
		}
		receipt, err := json.MarshalIndent(map[string]any{
			"mode": mode, "status": "passed", "recipient": verified,
			"replay": replay,
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, mode+".json"), receipt, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func representation(mime string, p payload) engine.ContentInput {
	return engine.ContentInput{Representations: []engine.RepresentationInput{{MIME: mime, Reader: bytes.NewReader(p.data), Size: int64(len(p.data))}}}
}

func fingerprints(payloads []payload) map[string]fingerprint {
	result := make(map[string]fingerprint, len(payloads))
	for _, payload := range payloads {
		hash := sha256.Sum256(payload.data)
		result[payload.name] = fingerprint{Size: len(payload.data), SHA256: hex.EncodeToString(hash[:])}
	}
	return result
}

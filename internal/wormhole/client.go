package wormhole

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const origin = "https://wormhole.app"

var roomID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Client struct {
	http http.Client
}

func New(transport http.RoundTripper) *Client {
	return &Client{http: http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type room struct {
	ID          string `json:"id"`
	WriterToken []byte `json:"writerToken"`
}

type uploadToken struct {
	URL           string `json:"uploadUrl"`
	Authorization string `json:"authorizationToken"`
}

func (c *Client) Share(ctx context.Context, files []File) (string, error) {
	if err := validate(files); err != nil {
		return "", err
	}
	spool, err := os.CreateTemp("", "unic-wormhole-*")
	if err != nil {
		return "", errors.New("wormhole: create encrypted spool failed")
	}
	defer os.Remove(spool.Name())
	defer spool.Close()
	master, salt := randomBytes(16), randomBytes(16)
	entries, size, err := spoolFiles(ctx, spool, master, files)
	if err != nil {
		return "", err
	}
	piece := make([]byte, pieceSize(size))
	metadata, infoHash, err := torrent(ctx, spool, entries, size, piece)
	if err != nil {
		return "", err
	}
	encrypted, err := encryptMetadata(master, salt, metadata)
	if err != nil {
		return "", err
	}
	reader, err := derive(master, salt, "authentication")
	if err != nil {
		return "", err
	}
	var created room
	if err := c.api(ctx, "create room", http.MethodPost, "/room", "", map[string]any{
		"readerToken": reader, "salt": salt,
	}, &created); err != nil {
		return "", err
	}
	if !roomID.MatchString(created.ID) || len(created.WriterToken) != 16 {
		return "", errors.New("wormhole: invalid room response")
	}
	path := "/room/" + created.ID
	writer := "Bearer sync-v1 " + base64.StdEncoding.EncodeToString(created.WriterToken)
	if err := c.api(ctx, "mark uploader online", http.MethodPatch, path+"/uploader-online", writer, nil, nil); err != nil {
		return "", err
	}
	if err := c.api(ctx, "publish metadata", http.MethodPatch, path, writer, map[string]any{
		"infoHash": infoHash, "encryptedTorrentFile": encrypted, "multiFile": len(files) > 1,
		"sizeMb": roundedMB(size),
	}, nil); err != nil {
		return "", err
	}
	if err := c.upload(ctx, spool, size, piece, created.ID, writer); err != nil {
		return "", err
	}
	if err := c.api(ctx, "finish upload", http.MethodPost, path+"/b2/finish-upload", writer, map[string]bool{"success": true}, nil); err != nil {
		return "", err
	}
	return origin + "/" + created.ID + "#" + base64.RawURLEncoding.EncodeToString(master), nil
}

func roundedMB(size int64) int64 {
	mb := (size + 500_000) / 1_000_000
	scale := int64(1)
	for mb > 100 {
		scale *= 10
		mb = (size + scale*500_000) / (scale * 1_000_000)
	}
	return mb * scale
}

func (c *Client) upload(ctx context.Context, spool *os.File, size int64, piece []byte, id, writer string) error {
	pieceLength := int64(len(piece))
	count := int((size + pieceLength - 1) / pieceLength)
	for start := 0; start < count; {
		n := min(10, count-start)
		var tokens []uploadToken
		if err := c.api(ctx, "authorize upload", http.MethodPost, "/room/"+id+"/b2/auth-upload", writer, map[string]int{"numTokens": n}, &tokens); err != nil {
			return err
		}
		if len(tokens) != n {
			return errors.New("wormhole: invalid upload authorization count")
		}
		for i, token := range tokens {
			index := start + i
			offset := int64(index) * pieceLength
			data := piece[:min(pieceLength, size-offset)]
			if _, err := spool.ReadAt(data, offset); err != nil {
				return errors.New("wormhole: read spool failed")
			}
			if err := c.uploadPiece(ctx, id, index, token, data); err != nil {
				return err
			}
		}
		start += n
	}
	return nil
}

func (c *Client) uploadPiece(ctx context.Context, id string, index int, token uploadToken, data []byte) error {
	target, err := url.Parse(token.URL)
	if err != nil || target.Scheme != "https" || target.User != nil || target.Port() != "" ||
		!strings.HasSuffix(target.Hostname(), ".backblaze.com") ||
		!strings.HasPrefix(target.Path, "/b2api/v") || target.RawQuery != "" || target.Fragment != "" ||
		token.Authorization == "" {
		return errors.New("wormhole: invalid upload authorization")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(data))
	if err != nil {
		return errors.New("wormhole: invalid upload request")
	}
	hash := sha1.Sum(data) // Required by Backblaze for ciphertext integrity.
	req.Header.Set("Authorization", token.Authorization)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Bz-File-Name", fmt.Sprintf("%s/%d", id, index))
	req.Header.Set("X-Bz-Content-Sha1", hex.EncodeToString(hash[:]))
	return c.send(req, "upload piece", nil)
}

func (c *Client) api(ctx context.Context, stage, method, path, credential string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("wormhole: %s: encode request failed", stage)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+"/api"+path, reader)
	if err != nil {
		return fmt.Errorf("wormhole: %s: invalid request", stage)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	if credential != "" {
		req.Header.Set("Authorization", credential)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req, stage, out)
}

func (c *Client) send(req *http.Request, stage string, out any) error {
	req.Header.Set("User-Agent", "UniClipboard-Wormhole/0.1")
	response, err := c.http.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return req.Context().Err()
		}
		return fmt.Errorf("wormhole: %s: request failed", stage)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("wormhole: %s: HTTP %d", stage, response.StatusCode)
	}
	const limit = 256 << 10
	if out == nil {
		_, err := io.Copy(io.Discard, io.LimitReader(response.Body, limit))
		if err != nil {
			return fmt.Errorf("wormhole: %s: response interrupted", stage)
		}
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(data) > limit || json.Unmarshal(data, out) != nil {
		return fmt.Errorf("wormhole: %s: invalid response", stage)
	}
	return nil
}

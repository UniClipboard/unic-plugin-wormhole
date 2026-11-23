package wormhole

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zeebo/bencode"
	"mz.attahri.com/code/ece/v2"
)

const (
	maxShareBytes = 5_000_000_000
	maxFiles      = 2048
	recordSize    = 64 << 10
)

type File struct {
	Name string
	Size int64
	Open func(context.Context) (io.ReadCloser, error)
}

func validate(files []File) error {
	if len(files) == 0 || len(files) > maxFiles {
		return errors.New("wormhole: invalid file count")
	}
	var size int64
	names := make(map[string]bool, len(files))
	for _, file := range files {
		name := file.Name
		key := strings.ToLower(name)
		if len(name) > 255 || !utf8.ValidString(name) || strings.TrimSpace(name) != name ||
			name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") ||
			strings.ContainsFunc(name, unicode.IsControl) || names[key] || file.Open == nil {
			return errors.New("wormhole: invalid or duplicate file name")
		}
		if file.Size < 0 || file.Size > maxShareBytes-size {
			return errors.New("wormhole: size limit exceeded")
		}
		size += file.Size
		names[key] = true
	}
	return nil
}

type fileEntry struct {
	Length int64    `bencode:"length"`
	Path   []string `bencode:"path"`
}

// Copy the source to a private, ciphertext-only spool. A selection is one
// torrent, so a torrent piece can cross an encrypted file boundary.
func encryptFile(ctx context.Context, out io.Writer, master []byte, file File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err := file.Open(ctx)
	if err != nil {
		return errors.New("wormhole: open source failed")
	}
	defer source.Close()
	writer, err := ece.NewWriter(master, randomBytes(16), recordSize, "", out)
	if err != nil {
		return errors.New("wormhole: initialize file encryption failed")
	}
	n, err := io.Copy(writer, io.LimitReader(source, file.Size+1))
	if err != nil || n != file.Size {
		return errors.New("wormhole: copy source failed")
	}
	if err := writer.Close(); err != nil {
		return errors.New("wormhole: finish file encryption failed")
	}
	return nil
}

func spoolFiles(ctx context.Context, spool *os.File, master []byte, files []File) ([]fileEntry, int64, error) {
	entries := make([]fileEntry, 0, len(files))
	var previous int64
	for _, file := range files {
		// Hide Close from the ECE writer so each file leaves the spool open.
		if err := encryptFile(ctx, struct{ io.Writer }{spool}, master, file); err != nil {
			return nil, 0, err
		}
		end, err := spool.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, 0, errors.New("wormhole: seek spool failed")
		}
		if end > maxShareBytes {
			return nil, 0, errors.New("wormhole: encrypted size limit exceeded")
		}
		entries = append(entries, fileEntry{Length: end - previous, Path: []string{file.Name}})
		previous = end
	}
	return entries, previous, nil
}

func torrent(ctx context.Context, spool *os.File, entries []fileEntry, size int64, piece []byte) ([]byte, string, error) {
	var hashes []byte
	for offset := int64(0); offset < size; offset += int64(len(piece)) {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		data := piece[:min(int64(len(piece)), size-offset)]
		if _, err := spool.ReadAt(data, offset); err != nil {
			return nil, "", errors.New("wormhole: read spool failed")
		}
		hash := sha1.Sum(data) // BitTorrent v1 piece checksums.
		hashes = append(hashes, hash[:]...)
	}
	info := map[string]any{
		"nonce":        hex.EncodeToString(randomBytes(16)),
		"piece length": len(piece),
		"pieces":       string(hashes),
		"private":      1,
	}
	if len(entries) == 1 {
		info["name"] = entries[0].Path[0]
		info["length"] = entries[0].Length
	} else {
		info["name"] = "files"
		info["files"] = entries
	}
	infoBytes, err := bencode.EncodeBytes(info)
	if err != nil {
		return nil, "", err
	}
	hash := sha1.Sum(infoBytes) // BitTorrent v1 info hash.
	const tracker = "wss://wormhole.app/websocket"
	body, err := bencode.EncodeBytes(map[string]any{
		"announce":      tracker,
		"announce-list": [][]string{{tracker}},
		"creation date": time.Now().Unix(),
		"info":          info,
		"private":       1,
		"url-list":      []string{},
	})
	return body, hex.EncodeToString(hash[:]), err
}

func pieceSize(size int64) int {
	const block = 16 << 10
	rounded := (min(size, 5_000_000) + block - 1) / block * block
	power := int64(math.Exp2(math.Round(math.Log2(float64(size) / 1024))))
	return int(max(block, power, rounded))
}

func randomBytes(n int) []byte {
	data := make([]byte, n)
	rand.Read(data)
	return data
}

func derive(master, salt []byte, label string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, salt, label, 16)
}

func encryptMetadata(master, salt, data []byte) ([]byte, error) {
	key, err := derive(master, salt, "metadata")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(aead.NonceSize())
	return aead.Seal(nonce, nonce, data, nil), nil
}

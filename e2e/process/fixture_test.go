package process

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zeebo/bencode"
	"mz.attahri.com/code/ece/v2"
)

// Map production hosts onto a local provider without changing the plugin's
// upload URL validation or sending any fixture traffic outside the process.
type fixtureTransport struct{ endpoint string }

func (f fixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(f.endpoint)
	if err != nil {
		return nil, err
	}
	copy := req.Clone(req.Context())
	copy.URL.Scheme, copy.URL.Host = target.Scheme, target.Host
	return http.DefaultTransport.RoundTrip(copy)
}

type providerFixture struct {
	server                 *httptest.Server
	fail                   atomic.Value
	completions            atomic.Int32
	mu                     sync.Mutex
	salt, metadata, reader []byte
	infoHash               string
	pieces                 [][]byte
}

const fixtureRoom = "/api/room/fixture"
const fixtureWriter = "Bearer sync-v1 AAAAAAAAAAAAAAAAAAAAAA=="

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	f := &providerFixture{}
	f.fail.Store("")
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *providerFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, fixtureRoom) && r.Header.Get("Authorization") != fixtureWriter {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/room":
		var request struct{ ReaderToken, Salt []byte }
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Salt) != 16 || len(request.ReaderToken) != 16 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.salt, f.reader, f.pieces, f.metadata = request.Salt, request.ReaderToken, nil, nil
		if f.fail.Load() == "malformed-room" {
			io.WriteString(w, `{"id":"../wrong","writerToken":"AAAAAAAAAAAAAAAAAAAAAA=="}`)
			return
		}
		io.WriteString(w, `{"id":"fixture","writerToken":"AAAAAAAAAAAAAAAAAAAAAA=="}`)
	case fixtureRoom + "/uploader-online":
	case fixtureRoom:
		var request struct {
			InfoHash             string
			EncryptedTorrentFile []byte
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.metadata, f.infoHash = request.EncryptedTorrentFile, request.InfoHash
	case fixtureRoom + "/b2/auth-upload":
		var request struct{ NumTokens int }
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.NumTokens < 1 || request.NumTokens > 10 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tokens := make([]map[string]string, request.NumTokens)
		for i := range tokens {
			tokens[i] = map[string]string{
				"uploadUrl":          "https://storage.backblaze.com/b2api/v2/b2_upload_file/fixture",
				"authorizationToken": "fixture",
			}
		}
		if f.fail.Load() == "malformed-authorization" {
			tokens[0]["uploadUrl"] = "https://backblaze.com.example.org/invalid"
		}
		json.NewEncoder(w).Encode(tokens)
	case "/b2api/v2/b2_upload_file/fixture":
		data, err := io.ReadAll(r.Body)
		hash := sha1.Sum(data)
		if err != nil || r.Header.Get("Authorization") != "fixture" ||
			r.Header.Get("X-Bz-File-Name") != fmt.Sprintf("fixture/%d", len(f.pieces)) ||
			r.Header.Get("X-Bz-Content-Sha1") != hex.EncodeToString(hash[:]) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.fail.Load() == "upload" || (f.fail.Load() == "partial-upload" && len(f.pieces) > 0) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.pieces = append(f.pieces, data)
	case fixtureRoom + "/b2/finish-upload":
		if f.fail.Load() == "finish" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var request struct{ Success bool }
		if json.NewDecoder(r.Body).Decode(&request) != nil || !request.Success || len(f.pieces) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.completions.Add(1)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type torrentFile struct {
	Length int64    `bencode:"length"`
	Path   []string `bencode:"path"`
}

func (f *providerFixture) download(t *testing.T, link string) downloadReceipt {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	fragment, ok := strings.CutPrefix(link, "https://wormhole.app/fixture#")
	master, err := base64.RawURLEncoding.DecodeString(fragment)
	if !ok || err != nil || len(master) != 16 {
		t.Fatal("invalid fixture link")
	}
	reader, err := hkdf.Key(sha256.New, master, f.salt, "authentication", 16)
	if err != nil || !bytes.Equal(reader, f.reader) {
		t.Fatal("reader token differs")
	}
	key, err := hkdf.Key(sha256.New, master, f.salt, "metadata", 16)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil || len(f.metadata) < 16 {
		t.Fatal("invalid encrypted torrent")
	}
	metadata, err := aead.Open(nil, f.metadata[:16], f.metadata[16:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var torrent struct {
		Info bencode.RawMessage `bencode:"info"`
	}
	if err := bencode.DecodeBytes(metadata, &torrent); err != nil {
		t.Fatal(err)
	}
	hash := sha1.Sum(torrent.Info)
	if hex.EncodeToString(hash[:]) != f.infoHash {
		t.Fatal("invalid info hash")
	}
	var info struct {
		PieceLength int           `bencode:"piece length"`
		Pieces      string        `bencode:"pieces"`
		Name        string        `bencode:"name"`
		Length      int64         `bencode:"length"`
		Files       []torrentFile `bencode:"files"`
	}
	if err := bencode.DecodeBytes(torrent.Info, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Pieces) != sha1.Size*len(f.pieces) {
		t.Fatal("piece count mismatch")
	}
	for i, data := range f.pieces {
		hash := sha1.Sum(data)
		if info.Pieces[i*sha1.Size:(i+1)*sha1.Size] != string(hash[:]) ||
			len(data) > info.PieceLength || (i < len(f.pieces)-1 && len(data) != info.PieceLength) {
			t.Fatal("invalid torrent piece")
		}
	}
	encrypted := bytes.Join(f.pieces, nil)
	files := info.Files
	if len(files) == 0 {
		files = []torrentFile{{Path: []string{info.Name}, Length: info.Length}}
	}
	var downloaded []payload
	for _, file := range files {
		if file.Length < 0 || file.Length > int64(len(encrypted)) || len(file.Path) != 1 {
			t.Fatal("invalid ciphertext file bounds")
		}
		clear, err := io.ReadAll(ece.NewReader(master, bytes.NewReader(encrypted[:file.Length])))
		if err != nil {
			t.Fatal(err)
		}
		downloaded = append(downloaded, payload{file.Path[0], clear})
		encrypted = encrypted[file.Length:]
	}
	if len(encrypted) != 0 {
		t.Fatal("unclaimed ciphertext")
	}
	return downloadReceipt{Lifetime: 86400, Files: fingerprints(downloaded)}
}

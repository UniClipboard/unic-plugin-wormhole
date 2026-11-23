#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
directory="${1:-.cache/package}"
mkdir -p "$directory"
directory=$(cd "$directory" && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' spec.toml)
test -n "$version"
export GOWORK=off CGO_ENABLED=0
for os in darwin linux windows; do
    for arch in amd64 arm64; do
        executable=unic-plugin-wormhole
        if [ "$os" = windows ]; then
            executable="$executable.exe"
        fi
        GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -o "$directory/$executable" ./cmd/unic-plugin-wormhole
        python3 - "$directory" "$version" "$os" "$arch" "$executable" <<'PY'
import gzip
import hashlib
import io
import pathlib
import sys
import tarfile

directory, version, goos, goarch, executable = sys.argv[1:]
directory = pathlib.Path(directory)
binary = (directory / executable).read_bytes()
asset = f"unic-plugin-wormhole_{goos}_{goarch}.tar.gz"
path = directory / asset
with path.open("wb") as output:
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            entry = tarfile.TarInfo(executable)
            entry.size = len(binary)
            entry.mode = 0o755
            archive.addfile(entry, io.BytesIO(binary))
digest = hashlib.sha256(path.read_bytes()).hexdigest()
print(f'''
[[artifacts]]
goos = "{goos}"
goarch = "{goarch}"
release = "v{version}"
asset = "{asset}"
executable = "{executable}"
sha256 = "{digest}"''')
(directory / executable).unlink()
PY
    done
done

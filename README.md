# pureadb — experimental pure-Go ADB library

`pureadb` is an experimental ADB client written in Go. It talks directly to Android's `adbd`; it does **not** execute `adb`, does not connect to the desktop ADB server on port 5037, does not use CGO, and currently has no third-party Go module dependencies.

The first milestone focuses on Android 11+ **Wireless Debugging**:

- Pair by Android's 6-digit Wi-Fi pairing code.
- Generate Android-compatible pairing QR payloads and PNG/SVG QR codes.
- Discover `_adb-tls-pairing._tcp` and `_adb-tls-connect._tcp` over mDNS.
- SPAKE2 + TLS pairing compatible with AOSP/BoringSSL.
- Persist an RSA-2048 ADB identity.
- Connect directly to `adbd` using `CNXN -> STLS -> TLS -> CNXN`.
- Open multiplexed ADB streams (`OPEN`, `OKAY`, `WRTE`, `CLSE`).
- Run shell commands and binary `exec:` commands.
- Push/pull files using the SYNC protocol.
- Install/uninstall APKs.
- List installed packages.
- Host-side TCP forwarding backed by direct ADB streams.
- Optional legacy RSA AUTH flow for older TCP ADB endpoints.

## Status

This is an **alpha / protocol implementation**, not yet a drop-in replacement for every feature in Google's Platform Tools. Unit/race tests pass, the library cross-compiles for Windows amd64 and Linux arm64, and its generated QR has been decoded successfully by an independent QR decoder. The current environment did not provide a physical Android device, so real-device pairing/connect/install must still be interoperability-tested on actual hardware before calling this production-ready.

## Module name

The sample module is intentionally:

```text
module github.com/example/pureadb
```

Change that line and the two internal import prefixes to your real repository path before publishing it. If you keep the tree as-is locally, the examples compile unchanged.

## Pair using the 6-digit code

On Android: Developer options -> Wireless debugging -> Pair device with pairing code.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    adb "github.com/example/pureadb"
)

func main() {
    key, err := adb.LoadOrCreateKey("adbkey.pem", "my-app@go")
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    // Empty serviceName = use the first visible pairing service.
    client, paired, err := adb.PairAndConnectCode(ctx, "", "123456", key)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    fmt.Println("GUID:", paired.GUID)
    fmt.Println("ADB:", paired.ConnectAddress)

    model, err := client.Shell(ctx, "getprop ro.product.model")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Print(model)
}
```

If your UI already knows the pairing host/port you can bypass mDNS:

```go
paired, err := adb.Pair(ctx, "192.168.1.50:41127", "123456", key)
```

## QR pairing

Android's ADB QR format is generated directly by the library:

```go
q, err := adb.NewQRSession()
if err != nil {
    return err
}

pngBytes, err := q.PNG(512)
if err != nil {
    return err
}
os.WriteFile("pair.png", pngBytes, 0644)

// Display the QR to the user before entering this wait.
client, paired, err := adb.PairAndConnectQR(ctx, q, key)
```

`q.Payload` looks like:

```text
WIFI:T:ADB;S:studio-XXXXXXXXXX;P:xxxxxxxxxxxxxxxx;;
```

The QR encoder is implemented in this repository (fixed Version 5-L / byte mode), so there is no QR dependency.

## Install an APK

```go
err := client.Install(ctx, `C:\builds\app-debug.apk`)
```

Advanced install flags:

```go
err := client.InstallAPK(ctx, "app.apk", adb.InstallOptions{
    Replace:                 true,
    GrantRuntimePermissions: true,
    AllowTest:               true,
})
```

The implementation pushes the APK through ADB SYNC to `/data/local/tmp/` and executes `pm install`, then deletes the temporary APK.

## Shell / exec

```go
out, err := client.Shell(ctx, "id")

rawPNG, err := client.Exec(ctx, "screencap -p")
```

For an interactive/streaming service:

```go
stream, err := client.ShellStream(ctx, "logcat")
if err != nil {
    return err
}
defer stream.Close()
io.Copy(os.Stdout, stream)
```

The current `Shell` path uses the classic shell service, so stdout/stderr are merged and the remote exit code is not exposed yet. `shell_v2` is a future milestone.

## Push / pull

```go
err := client.Push(ctx, "local.zip", "/sdcard/Download/local.zip", 0644)
err = client.Pull(ctx, "/sdcard/Download/result.json", "result.json")
```

The current implementation uses SYNC v1 with 64 KiB DATA chunks. Compression and `sendrecv_v2` are not implemented yet.

## TCP forwarding

```go
forward, err := client.ForwardTCP(ctx, "127.0.0.1:8080", 8080)
if err != nil {
    return err
}
defer forward.Close()
fmt.Println("listening on", forward.Addr())
```

## Keep the ADB identity persistent

Do not generate a new RSA key on every run if you want the phone to recognize the same host later:

```go
key, err := adb.LoadOrCreateKey("adbkey.pem", "my-app@go")
```

Store that private key with application-appropriate permissions. The public half is what Android authorizes during pairing.

## Architecture

```text
Your app
  |
  +-- pureadb
       |
       +-- mDNS discovery
       +-- QR encoder
       +-- TLS pairing
       +-- SPAKE2 (Edwards25519)
       +-- AES-128-GCM / HKDF-SHA256
       +-- RSA ADB identity / X.509
       +-- ADB packet transport
       +-- multiplexed streams
       +-- shell / exec
       +-- sync push/pull
       +-- package install
       +-- TCP forwarding
             |
             +---- Wi-Fi/TCP ----> Android adbd
```

There is no local `adb server` process in this architecture.

## Not implemented yet

- Native USB transport. This needs OS-specific USB backends (WinUSB on Windows; usbfs on Linux, etc.) while keeping the public API portable.
- `shell_v2` stdout/stderr/exit-code framing.
- SYNC v2 and compression (brotli/lz4/zstd).
- Reverse forwarding.
- JDWP helpers.
- framebuffer/screenshot helper wrappers (raw `Exec("screencap -p")` is already available).
- exhaustive IPv6/interface-aware mDNS. The current resolver sends IPv4 legacy-unicast mDNS queries and parses both A and AAAA records when returned.

## Validation in this snapshot

```text
go test -race ./...       PASS
go vet ./...              PASS
GOOS=windows GOARCH=amd64 go build ./...   PASS
GOOS=linux   GOARCH=arm64 go build ./...   PASS
```

Core tests cover SPAKE2 key agreement, AES-GCM duplex sequencing, ADB RSA public-key encoding, ADB packet framing, mDNS response parsing and QR PNG generation.

## Protocol references

The implementation was derived from public AOSP/BoringSSL protocol source rather than by wrapping Platform Tools. Useful upstream files include:

- AOSP `packages/modules/adb/docs/dev/adb_wifi.md`
- AOSP `packages/modules/adb/pairing_connection/`
- AOSP `packages/modules/adb/pairing_auth/`
- AOSP `packages/modules/adb/adb.cpp`
- AOSP `system/core/adb/protocol.txt`
- AOSP `system/core/adb/SYNC.TXT`
- BoringSSL `crypto/curve25519/spake25519.cc`

## Security note

The TLS peer certificate is deliberately not PKI-verified during ADB pairing/secure-connect because ADB uses its own pairing/authorized-key model with self-signed certificates. Pairing authenticity comes from the user-visible pairing code or QR shared secret, SPAKE2, and the stored ADB key. Treat the private ADB key as a credential.

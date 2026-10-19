# Android

An Android app that runs the wiresteward agent as a `VpnService`.

The agent itself is not duplicated here. `internal/agent` in the repo root is
the platform independent core (config, oauth login, lease requests, health
checks, status). The platform provides the network device behind the
`agent.Device` interface:

| Platform | Device implementation |
|---|---|
| linux, darwin (`main.go`) | `internal/hostdev`: a wireguard-go tun or a kernel wireguard device, configured with netlink/route sockets and wgctrl |
| android (`android/mobile`) | `tunnel`: one VPN interface backed by wireguard-go, built on the fd of `VpnService.Builder` |

`android/` is its own Go module that depends on the root module with a
`replace` directive, so the root `go.mod` carries no Android or gomobile
dependencies. Go allows it to import the root's `internal/` packages because
the import path is under the root module path.

## `mobile` package

Bound into the app with `gomobile bind`: `Start`, `Stop`, `Status` and the
`TunProvider` callback interface.

- Android allows one VPN interface per app, so all the configured devices
  share one `tunnel`: one private key, one wireguard-go device, one peer per
  device and the union of their allowed IPs as routes. The interface is
  re-established only when the set of routes changes, other lease changes are
  applied to the running device.
- The tun has a single fixed address, `100.64.255.254/32`. `natTun` rewrites
  the source address of outgoing packets to the address leased by the server
  that owns the destination, and the destination address of incoming ones
  back, because servers drop packets from any other source.
- `tun.CreateUnmonitoredTUNFromFD` is used since apps cannot open the netlink
  socket that `tun.CreateTUNFromFile` needs. The config is applied in-process
  with `Device.IpcSet` because the UAPI socket directory is not writable.
- `internal/agent/ping_android.go` uses an unprivileged ICMP socket for the
  health checks because raw sockets are denied.

## App contract

- Call `mobile.Start(configPath, filesDir, "", "error", provider)`.
- `provider.Establish(address, prefixLen, routes, mtu)` must build the VPN
  with `VpnService.Builder` (`addAddress`, one `addRoute` per newline separated
  CIDR in `routes`, `setMtu`) and return `ParcelFileDescriptor.detachFd()`.
- Login: open `http://localhost:7773/renew` in the browser. The redirect lands
  on the agent's loopback server, so the IdP client keeps its existing
  `http://localhost:7773/oauth2/callback` redirect URI.
- `Mobile.status()` returns the token validity and per device lease, routes
  and health as JSON.

## Build

You need JDK 17, the Android SDK and NDK 27.2.12479018:

```
export JAVA_HOME=... ANDROID_HOME=... ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
./build-aar.sh                 # Go agent -> app/libs/mobile.aar (gomobile is pinned in go.mod)
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew :app:assembleDebug   # app/build/outputs/apk/debug/app-debug.apk
```

## Release

The `android` job in `.github/workflows/goreleaser.yaml` runs for every tag,
after goreleaser has created the release. It builds a release APK signed with
the release keystore and attaches `wiresteward-android-<version>.apk` to the
release.

- Secrets: `ANDROID_KEYSTORE_BASE64` (the PKCS12 keystore, base64 encoded),
  `ANDROID_KEYSTORE_PASSWORD` and `ANDROID_KEY_PASSWORD`. Variable:
  `ANDROID_KEY_ALIAS`.
- The same key has to sign every release, Android only updates an app that is
  signed by the key of the installed one. Keep a backup of the keystore.
- `versionName` is the tag without the leading `v`. `versionCode` is
  `major*10000000 + minor*10000 + patch*10 + r`, where `r` is the number of a
  `-RCn` tag and 9 for a final release.
- To build a signed APK locally set `ANDROID_KEYSTORE_PATH`,
  `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_PASSWORD` and `ANDROID_KEY_ALIAS`
  and run `./gradlew :app:assembleRelease`. Without them the release build is
  unsigned.

## One device per user

The wiresteward servers keep one lease per user, keyed by the user name in the
token. A second client of the same user, with a different key, replaces the
first one's key until it renews. The phone and a laptop of the same user
cannot be connected at the same time.

## App

`app/` is a minimal Kotlin app: `MainActivity` (import the config, start/stop,
login, token and per device status) and `WirestewardVpnService`, which hosts
the agent and implements `TunProvider`. The config is the same JSON as
`examples/agent.json`, imported into the app's files dir. It is not part of
the APK.

## Not done

- `VpnService.protect()` for the WireGuard UDP socket (only matters if the
  server endpoint is inside the allowed IPs).
- The tun interface is re-established once per lease at startup.

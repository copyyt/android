# Copyyt for Android

Native Kotlin/Compose client that joins a Copyyt account as a **paired device**.
It speaks the same v1 protocol as the Chrome extension (Ed25519 signatures,
X25519 + HKDF-SHA256 key wrapping, AES-256-GCM payloads) over the existing
encrypted relay.

## What v1 does
- Email-code sign-in (Google sign-in needs its own Android OAuth client; later).
- Registers as a pending `android` device and pairs with the account root
  (the Chrome extension) by comparing a fingerprint. Android never becomes the
  account root: the first device must be Chrome, which holds the offline
  recovery credential.
- Trusts other devices only through approval certificates signed by the
  pinned root — never because the server says so.
- Receives `text/plain` automatically: a foreground service keeps the socket
  open, decrypts, writes the clipboard and posts a notification (no content in
  the notification).
- Sends manually (Android 10+ blocks background clipboard reads): the in-app
  button, **Share → Copyyt**, or the **Send clipboard** quick-settings tile.
- Advertises only the `clipboard` capability, so other devices send it plain
  text (no HTML/PNG bundles, no direct WebRTC yet).

Keys, tokens and trust state are encrypted with a non-exportable Android
Keystore AES-GCM key (`noBackupFilesDir/copyyt-state`).

## Build and run
```
./gradlew :app:assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:testDebugUnitTest    # protocol interop + sync engine tests
./gradlew :app:connectedDebugAndroidTest   # Keystore storage, needs a device
```
Endpoints default to production. For a LAN backend add to `local.properties`:
```
copyyt.apiUrl=http://192.168.0.121:8000
copyyt.socketUrl=http://192.168.0.121:8001
```
Debug builds allow cleartext HTTP; release builds do not.

## Protocol interop
`tools/protocol-fixture.ts` runs the extension's own crypto:
```
node --experimental-strip-types tools/protocol-fixture.ts generate
node --experimental-strip-types tools/protocol-fixture.ts verify app/build/android-envelope.json
```
`generate` rewrites `app/src/test/resources/protocol-fixture.json` (Chrome →
Android); `ProtocolFixtureTest` must match it byte for byte. `verify` makes the
extension decrypt the envelope the Kotlin tests wrote (Android → Chrome).

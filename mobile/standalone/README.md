# BPS Companion

Pay and receive BPS from your phone, with no coin keys on the phone.

Your own BPS Relay at home keeps a small **allowance wallet** and signs for
the phone, within rules only the relay can change:

- **Limits.** So much per payment and so much a day, set when you pair the phone.
- **PIN.** Checked by the relay. Five wrong tries lock the phone until you
  unlock it on the relay.
- **Unpairing.** The relay can unpair the phone at any time; it can then do nothing more.

The phone holds only a key of its own, kept in the Android Keystore or the
desktop's keyring, and that key can spend nothing by itself. The phone is not a
node: it keeps no blockchain, uses network only while the app is open, and
never carries anyone else's traffic.

## What you need

- **A computer running BPS Relay** with the *Phone companion* card on its
  Server page, left running while you want to pay from the phone.
- **One of these:**
  - **Android 9 or later.** Most phones take the `arm64-v8a` package, older
    32-bit phones `armeabi-v7a`, and emulators and some Chromebooks `x86_64`.
  - **Linux with Flatpak.** This covers desktops and phones running
    postmarketOS, Mobian or Plasma Mobile, on x86_64 or aarch64.

## Install

### Android

1. From the [Releases](https://github.com/Catipal/companion-app/releases) page,
   download `bps-companion-<version>-arm64-v8a.apk` (or the package for your
   phone, see above).
2. Open the file. When Android asks, allow your browser or Files app to install
   apps, then tap **Install**.
3. Optionally, check the download first. Its SHA-256 is in `SHA256SUMS` on the
   same release, and the signing certificate must be the project's:

   ```
   apksigner verify --print-certs bps-companion-<version>-arm64-v8a.apk
   ```

   The certificate's SHA-256 fingerprint is printed in each release's notes.

**Updates:** install the newer package over the old one. Every release is
signed with the same key, so the app keeps its pairing. [Obtainium](https://github.com/ImranR98/Obtainium)
can watch the Releases page and offer updates without any account.

### Linux (Flatpak)

```
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user bps-companion-<version>-x86_64.flatpak
flatpak run org.bps.companion
```

Use the `aarch64` bundle on ARM phones and computers. The app keeps its key in
the desktop's keyring (GNOME Keyring, KWallet or another Secret Service), and
falls back to a file only you can read where there is none.

## Set up your relay

On the computer, in BPS Relay, open **Server** and find the **Phone companion**
card:

1. Tick **Let paired phones spend from an allowance wallet** and restart BPS Relay.
2. Click **Create it** to make the allowance wallet, then **Top up…** to send
   it a small amount from your main wallet. The allowance wallet has no
   passphrase, because nobody is there to type one when the phone pays, so
   keep its balance small.
3. Click **Pair a phone…**. A QR code appears, good for ten minutes and for one phone.

A phone can be paired before the allowance wallet exists. It then shows that
it cannot pay yet, and shows the balance once the wallet is there.

## Pair the phone

1. Open BPS Companion and tap **Scan the code**. Allow the camera when asked,
   and point it at the code on the computer's screen. You can also paste the
   text under the code.
2. Give the phone a name and choose a PIN of six to twelve digits.
3. Both screens now show six digits. Check that they match.
4. On the computer, accept the phone and set its limits: the most it may send
   in one payment, and in one day.

## Reaching your relay

- **On the same Wi-Fi as the computer**, the phone connects straight to it.
  Windows may ask whether to allow BPS Relay on the network; allow it on
  private networks.
- **Away from home** there are two ways:
  - **Your relay is listed as a relay** (the Relay card on the Server page).
    The phone reaches it through three other relays, picked by the phone, so
    none of them, and nobody watching your home connection, learns where the
    phone is.
  - **Your router forwards UDP port 48931 to the computer.** The card shows the
    port if you changed it. The phone then connects straight to your relay,
    and the network the phone is on can see that it talks to your relay.

The app shows on its Home screen when it is connected straight to the relay,
and Settings shows which way it connects.

## If the phone is lost or stolen

- **Unpair it.** On the computer, select the phone on the Phone companion card
  and click **Unpair**. From then on it can do nothing.
- **Until then** a thief still needs your PIN, and five wrong tries lock the
  phone. Nothing on the phone can spend by itself, and the most anyone could
  ever take is the allowance wallet's balance, within the limits you set.
- **To find the phone**, use your phone maker's service: on Android, Google's
  Find My Device. The app does not track where the phone is.

## Build from source

The app is C++ and QML on Qt 6 (written to the Qt 6.8 API, released with
6.12), with [ZXing-C++](https://github.com/zxing-cpp/zxing-cpp) for QR codes and
[QtKeychain](https://github.com/frankosterfeld/qtkeychain) for the device key.

**Linux desktop.** You need Qt 6.8 or later (Base, Declarative, Multimedia,
ShaderTools, Svg), ZXing-C++ 3 and QtKeychain built for Qt 6, plus CMake 3.21
and Ninja:

```
cmake -S app -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/bps-companion
```

**Android.** `tools/android.sh [abi...]` builds Qt 6.12, ZXing-C++ and
QtKeychain for Android from source, checks every download against its
checksum, and writes unsigned packages to `~/bps-mobile/out`. The script's
header lists what it needs: a JDK 21, the Android SDK and NDK, CMake, Ninja
and the OpenGL headers (on Debian and Ubuntu, `libgl-dev` and `libegl-dev`).

**Flatpak:**

```
flatpak-builder --user --install --force-clean build flatpak/org.bps.companion.yml
```

**Without a screen.** `cmake -S core -B build-core && cmake --build build-core`
builds `bps-companion-cli`, the same client as a command-line program, which
is handy for testing against a relay.

## Repository layout

| Folder | What it holds |
| --- | --- |
| `app/` | The app: QML screens, the backend, and Android and Linux packaging |
| `core/` | The client library the app is built on: the encrypted overlay client and the companion protocol |
| `compat/` | Small stand-ins for the parts of the node the client does not need |
| `shared/` | The BPS node's own source files the client compiles, copied unchanged; see `shared/README.md` |
| `tools/` | `android.sh`, the Android build |
| `flatpak/`, `fdroid/` | The Flatpak manifest and a draft F-Droid recipe |

Making a release is described in [RELEASING.md](RELEASING.md).

## Licence

MIT; see [COPYING](COPYING). The files under `shared/` carry their own
notices, all MIT-compatible.

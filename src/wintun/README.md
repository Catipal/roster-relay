Wintun
======

`wintun.h` is the API header of Wintun 0.14.1, the layer-3 TUN driver for
Windows made by WireGuard LLC (https://www.wintun.net). It is copied
unmodified from `wintun-0.14.1.zip`:

- downloaded 2026-10-17 from https://www.wintun.net/builds/wintun-0.14.1.zip,
  with approval;
- 750,540 bytes, SHA-256
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, the
  checksum wintun.net publishes;
- `wintun.h` itself: SHA-256
  `510a5984fbf73efd21a61ada60edfe05e1a38a77c8c47f6d62e0ab1cdbdd460f`.

The header is licensed "GPL-2.0 OR MIT" (its first line), and is used here
under MIT.

The driver itself is not in this tree. It ships as the signed `wintun.dll`
from the same archive, beside `bps-relay-net.exe` in BPS Relay's Windows
package (see `.github/workflows/release.yml`), under the archive's own
"Prebuilt Binaries License": it may be distributed alongside software that
uses it only through the API in `wintun.h`, it must not be modified, and the
names of WireGuard LLC, WireGuard and Wintun must not be used to endorse or
promote BPS. The licence text goes into the package as `wintun-license.txt`.

DLL checksums in the 0.14.1 archive:

| Architecture | SHA-256 |
| --- | --- |
| amd64 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| x86 | `d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931` |
| arm64 | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |
| arm | `daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9` |

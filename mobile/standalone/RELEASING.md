# Making a release

GitHub builds the packages; you sign the Android ones on your own computer
with the release key, which never goes to GitHub. A release takes about an hour
of build time, most of it the first time, while Qt for Android is built and cached.

## The release key (once)

Make the key on a computer you trust, and keep the keystore and its password
backed up offline. Every later release must be signed with the same key, or
phones refuse it as an update.

```
keytool -genkeypair -keystore bps-release.keystore -alias bps -keyalg EC \
  -groupname secp256r1 -validity 10000 -dname "CN=BPS Companion"
```

The name in `-dname` is what the certificate shows; use the project's name,
not your own. Print the fingerprint you will publish with each release:

```
keytool -list -v -keystore bps-release.keystore -alias bps | grep SHA256
```

## Each release

1. **Version.** In `app/CMakeLists.txt`, raise `VERSION` in `project(...)`
   (e.g. `0.2.0`) and `QT_ANDROID_VERSION_CODE` by one. Android only installs
   an update whose version code is higher.
2. **What changed.** Add a section for the version at the top of
   `CHANGELOG.md`, and the same text, a few lines, as
   `app/fastlane/metadata/android/en-US/changelogs/<version code>.txt`.
3. **Commit, tag and push:**

   ```
   git commit -am "Release 0.2.0"
   git tag v0.2.0
   git push origin main v0.2.0
   ```

   The tag starts the *Release* workflow. It builds unsigned APKs for the
   three Android ABIs and Flatpak bundles for x86_64 and aarch64, and opens a
   **draft** release holding them, with the changelog section as its notes.
4. **Sign the APKs.** Download the three `*-unsigned.apk` files from the
   draft, then for each one (`apksigner` and `zipalign` are in the Android
   SDK's `build-tools`):

   ```
   zipalign -p -f 4 bps-companion-0.2.0-arm64-v8a-unsigned.apk aligned.apk
   apksigner sign --ks bps-release.keystore --ks-key-alias bps \
     --out bps-companion-0.2.0-arm64-v8a.apk aligned.apk
   apksigner verify --print-certs bps-companion-0.2.0-arm64-v8a.apk
   ```

   The certificate printed must have the fingerprint you published.
5. **Checksums.** Next to the signed APKs and the downloaded `.flatpak` files:

   ```
   sha256sum *.apk *.flatpak > SHA256SUMS
   ```

   Leave the unsigned APKs out of this folder first.
6. **Publish.** In the draft, delete the unsigned APKs and upload the signed
   ones and `SHA256SUMS`. Add the certificate fingerprint to the notes, and
   publish.

## F-Droid (later)

`fdroid/org.bps.companion.yml` is a draft of the recipe F-Droid needs. F-Droid
builds the app itself from the tagged source and signs it with its own key,
unless reproducible builds are set up so it can ship yours. Fill in the release
commit, check the build with `fdroid build`, and submit it to
[fdroiddata](https://gitlab.com/fdroid/fdroiddata).

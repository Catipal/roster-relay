// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_APP_DEVICEKEY_H
#define BPS_MOBILE_APP_DEVICEKEY_H

#include <key.h>

#include <QString>

/**
 * The device key, made on first run and kept in the system's keystore: the
 * Android Keystore, or the Secret Service (GNOME Keyring, KWallet) on Linux.
 * Where there is none - a bare desktop, WSL - it falls back to a file only
 * this user can read, and `in_keystore` says so; a file left by an earlier
 * run moves into the keystore as soon as one is there.
 *
 * Either way it can spend nothing by itself: the home node also wants the PIN.
 * `dir` tells apart the keys of several data folders on one machine.
 */
bool LoadOrMakeDeviceKey(const QString& dir, CKey& key, bool& in_keystore, QString& error);

#endif // BPS_MOBILE_APP_DEVICEKEY_H

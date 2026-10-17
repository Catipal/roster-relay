// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_NETSERVICE_H
#define BITCOIN_OVERLAY_NETSERVICE_H

#include <stddef.h>
#include <stdint.h>

/**
 * Between BPS Relay and its network service on Windows (bps-relay-net.cpp).
 *
 * On Windows the system-wide interface is a Wintun adapter, and making one,
 * and changing the computer's routes, needs an administrator. By design,
 * a small service installed once does that: it owns the
 * adapter, its addresses, its resolver and the routes, and passes packets to
 * and from BPS Relay over a named pipe only the user who installed it may
 * open. BPS Relay itself runs without an administrator's rights.
 *
 * On the pipe, frames: type (1 byte), 0, length (2 bytes, little-endian),
 * then that many bytes. BPS Relay starts with HELLO; after it, PACKET frames
 * go both ways, one IP packet each. NOTE frames carry a line of text from the
 * service for BPS Relay's log.
 */
namespace overlay {

static const wchar_t* const NET_SERVICE_PIPE = L"\\\\.\\pipe\\bps-relay-net";
static const wchar_t* const NET_SERVICE_NAME = L"BPSRelayNet";
static const wchar_t* const NET_SERVICE_ADAPTER = L"BPS Relay";

enum NetServiceFrame : uint8_t {
    NS_PACKET = 1,
    NS_HELLO = 2, //!< one byte of flags
    NS_NOTE = 3,
};

/** HELLO flag: route the whole computer through the adapter, not only what is routed to it. */
static constexpr uint8_t NS_ROUTE_COMPUTER = 1;

static constexpr size_t NS_HEADER = 4;
static constexpr size_t NS_MAX_FRAME = 0xffff;

} // namespace overlay

#endif // BITCOIN_OVERLAY_NETSERVICE_H

// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_NETSTACK_H
#define BITCOIN_OVERLAY_NETSTACK_H

/**
 * The node's own TCP/IP stack (design note §8·7).
 *
 * A gateway carries a visitor's IP packets, and holding TCP connections for
 * them without administrator rights takes a stack in user space: lwIP,
 * vendored in src/lwip and configured in overlay/lwip/lwipopts.h. lwIP keeps
 * its state in globals, so there is one stack per process, and it is not
 * thread-safe: everything that touches it runs on the one thread that owns
 * it, and InitNetStack runs before any of that.
 */
namespace overlay {

/** Initialise lwIP, once per process. Safe to call again. */
void InitNetStack();

} // namespace overlay

#endif // BITCOIN_OVERLAY_NETSTACK_H

// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <compat.h>
#include <netaddress.h>
#include <serialize.h>

#include <stdint.h>
#include <string>
#include <vector>

extern int nConnectTimeout;
extern bool fNameLookup;

//! -timeout default
static const int DEFAULT_CONNECT_TIMEOUT = 5000;
//! -dns default
static const int DEFAULT_NAME_LOOKUP = true;

class proxyType
{
public:
    proxyType(): randomize_credentials(false) {}
    explicit proxyType(const CService &_proxy, bool _randomize_credentials=false): proxy(_proxy), randomize_credentials(_randomize_credentials) {}

    bool IsValid() const { return proxy.IsValid(); }

    CService proxy;
    bool randomize_credentials;
};

enum Network ParseNetwork(const std::string& net);
std::string GetNetworkName(enum Network net);
bool SetProxy(enum Network net, const proxyType &addrProxy);
bool GetProxy(enum Network net, proxyType &proxyInfoOut);
bool IsProxy(const CNetAddr &addr);
bool SetNameProxy(const proxyType &addrProxy);
bool HaveNameProxy();
bool GetNameProxy(proxyType &nameProxyOut);
bool LookupHost(const std::string& name, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup);
bool LookupHost(const std::string& name, CNetAddr& addr, bool fAllowLookup);
bool Lookup(const std::string& name, CService& addr, int portDefault, bool fAllowLookup);
bool Lookup(const std::string& name, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions);
CService LookupNumeric(const std::string& name, int portDefault = 0);
bool LookupSubNet(const std::string& strSubnet, CSubNet& subnet);
SOCKET CreateSocket(const CService &addrConnect);

/**
 * The node's own sockets carry this mark when the computer's traffic is
 * routed through the overlay's interface, so that routes pass them by and
 * the node's own traffic - peer-to-peer, the overlay, a gateway's exits -
 * never goes into the interface it serves (overlay/sysroute.h). 0 is off.
 * Linux only (SO_MARK, which needs CAP_NET_ADMIN).
 */
void SetBypassMark(uint32_t mark);
uint32_t GetBypassMark();
/**
 * Windows has no marks: there the node's own sockets are bound to the
 * computer's own interface instead (IP_UNICAST_IF), by its index for IPv4
 * and for IPv6, which no route can redirect. 0 is off.
 */
void SetBypassInterfaces(uint32_t v4_index, uint32_t v6_index);
/** Give `s` the bypass mark when one is set. False when it is set and could not be given. */
bool MarkBypass(SOCKET s);
bool ConnectSocketDirectly(const CService &addrConnect, const SOCKET& hSocketRet, int nTimeout, bool manual_connection);
bool ConnectThroughProxy(const proxyType &proxy, const std::string& strDest, int port, const SOCKET& hSocketRet, int nTimeout, bool& outProxyConnectionFailed);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(const SOCKET& hSocket, bool fNonBlocking);
/** Set the TCP_NODELAY flag on a socket */
bool SetSocketNoDelay(const SOCKET& hSocket);
/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);
void InterruptSocks5(bool interrupt);

#endif // BITCOIN_NETBASE_H

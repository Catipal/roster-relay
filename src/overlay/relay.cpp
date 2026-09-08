// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/relay.h>

#include <logging.h>
#include <util/time.h>

namespace overlay {

std::unique_ptr<Relay> g_overlay;

Relay::Relay(const CKey& static_key) : m_socket(static_key), m_secret(static_key) {}

bool Relay::Bind(const CService& listen_addr, std::string& error)
{
    return m_socket.Bind(listen_addr, error);
}

bool Relay::Start(AppHandler app, PathHandler path)
{
    m_app = std::move(app);
    m_path = std::move(path);
    return m_socket.Start([this](const CService& from, std::vector<unsigned char>&& msg) {
        OnMessage(Hop::Direct(from), std::move(msg));
    });
}

void Relay::Stop() { m_socket.Stop(); }

bool Relay::Connect(const CService& peer, const CPubKey& peer_static)
{
    return m_socket.Connect(peer, peer_static);
}

bool Relay::SendApp(const CService& peer, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> msg;
    if (!EncodeAppData(payload, msg)) return false;
    return m_socket.Send(peer, msg);
}

bool Relay::SendToHop(const Hop& to, const std::vector<unsigned char>& msg)
{
    if (!to.via_path) return m_socket.Send(to.addr, msg);

    // A path hop: seal for the far end of that path, wrap as path traffic, and
    // hand it to whichever hop carries that path. The recursion is the onion -
    // one wrapping per leg, applied from the inside out.
    std::vector<unsigned char> sealed;
    Hop carrier;
    {
        LOCK(m_mutex);
        if (!m_secret.Send(to.path, msg, sealed)) return false;
        if (!m_paths.Carrier(to.path, carrier)) return false;
    }

    std::vector<unsigned char> wrapped;
    if (!EncodePathData(to.path, sealed, wrapped)) return false;
    return SendToHop(carrier, wrapped);
}

bool Relay::BuildPath(uint64_t path_id, const Hop& via, const CService& dest)
{
    std::vector<unsigned char> msg;
    if (!EncodePathBuild(path_id, dest, msg)) return false;
    return SendToHop(via, msg);
}

bool Relay::SendOnPath(uint64_t path_id, const std::vector<unsigned char>& inner)
{
    Hop carrier;
    {
        LOCK(m_mutex);
        if (!m_paths.Carrier(path_id, carrier)) return false;
    }
    std::vector<unsigned char> msg;
    if (!EncodePathData(path_id, inner, msg)) return false;
    return SendToHop(carrier, msg);
}

bool Relay::ConnectSecret(uint64_t path_id, const CPubKey& far_static)
{
    std::vector<unsigned char> hello;
    {
        LOCK(m_mutex);
        if (!m_secret.Connect(path_id, far_static, hello)) return false;
    }
    // The handshake rides the path as ordinary traffic. Relays forward it and
    // cannot complete it: only the holder of far_static can.
    return SendOnPath(path_id, hello);
}

bool Relay::HasSecretSession(uint64_t path_id)
{
    LOCK(m_mutex);
    return m_secret.HasSession(path_id);
}

bool Relay::SendSecretRaw(uint64_t path_id, const std::vector<unsigned char>& msg)
{
    std::vector<unsigned char> sealed;
    {
        LOCK(m_mutex);
        if (!m_secret.Send(path_id, msg, sealed)) return false;
    }
    return SendOnPath(path_id, sealed);
}

bool Relay::SendSecret(uint64_t path_id, const std::vector<unsigned char>& payload)
{
    // Wrapped as a message before sealing, because what comes out of an
    // end-to-end session is dispatched rather than delivered - that is how a
    // relay is asked to extend a path, and application data has to be
    // distinguishable from that asking.
    std::vector<unsigned char> msg;
    if (!EncodeAppData(payload, msg)) return false;

    std::vector<unsigned char> sealed;
    {
        LOCK(m_mutex);
        if (!m_secret.Send(path_id, msg, sealed)) return false;
    }
    return SendOnPath(path_id, sealed);
}

bool Relay::Introduce(uint64_t path_id, const roster::KeyBytes& service)
{
    std::vector<unsigned char> msg;
    if (!EncodeIntroduce(service, msg)) return false;
    // Sealed, so the relays carrying the path cannot see which service is
    // registering - only the rendezvous point at the far end learns that.
    return SendSecretRaw(path_id, msg);
}

bool Relay::Meet(uint64_t path_id, const roster::KeyBytes& service, uint64_t meet_id)
{
    std::vector<unsigned char> msg;
    if (!EncodeMeet(service, meet_id, msg)) return false;
    return SendSecretRaw(path_id, msg);
}

size_t Relay::IntroductionCount()
{
    LOCK(m_mutex);
    return m_intros.size();
}

size_t Relay::PathCount()
{
    LOCK(m_mutex);
    return m_paths.Size();
}

void Relay::OnMessage(const Hop& from, std::vector<unsigned char>&& msg)
{
    MessageKind kind;
    // Unrecognised messages are dropped without a reply. The sender is
    // authenticated, so this is a version difference rather than an attack, and
    // answering it tells an observer the two disagree.
    if (!DecodeKind(msg, kind)) return;

    switch (kind) {
    case MessageKind::APP_DATA: {
        std::vector<unsigned char> payload;
        if (!DecodeAppData(msg, payload)) return;
        if (m_app) m_app(from, std::move(payload));
        return;
    }

    case MessageKind::PATH_BUILD: {
        uint64_t path_id = 0;
        CService dest;
        if (!DecodePathBuild(msg, path_id, dest)) return;

        // Only join peers already known here. Building a path to a host this
        // node has never spoken to would let a stranger name any address and
        // have the relay dial it, which is an open proxy rather than an
        // overlay relay.
        const Hop dest_hop = Hop::Direct(dest);
        bool ok = m_socket.HasSession(dest) && dest_hop != from;
        if (ok) {
            LOCK(m_mutex);
            m_paths.Expire(GetTime());
            ok = m_paths.Create(path_id, from, dest_hop, GetTime());
        }

        if (ok) {
            // Tell the far end it is this path's endpoint, or it would drop
            // everything forwarded to it, having never asked for a path.
            std::vector<unsigned char> bind;
            if (EncodePathBind(path_id, bind)) SendToHop(dest_hop, bind);
        }

        std::vector<unsigned char> reply;
        if (EncodePathResult(ok, path_id, reply)) SendToHop(from, reply);
        return;
    }

    case MessageKind::PATH_OK:
    case MessageKind::PATH_FAIL: {
        bool ok = false;
        uint64_t path_id = 0;
        if (!DecodePathResult(msg, ok, path_id)) return;
        if (ok) {
            // The originator is an end of its own path too. Without an entry
            // here it sends fine and drops every reply, because return traffic
            // arrives on a path it has not recorded itself as an end of.
            LOCK(m_mutex);
            m_paths.CreateEndpoint(path_id, from, GetTime());
        }
        if (m_path) m_path(path_id, ok);
        return;
    }

    case MessageKind::PATH_BIND: {
        uint64_t path_id = 0;
        if (!DecodePathBind(msg, path_id)) return;
        LOCK(m_mutex);
        m_paths.Expire(GetTime());
        m_paths.CreateEndpoint(path_id, from, GetTime());
        return;
    }

    case MessageKind::INTRODUCE: {
        roster::KeyBytes service;
        if (!DecodeIntroduce(msg, service)) return;
        // Only over a path: a service registering from an address would have
        // just told the relay where it is, which is the one thing it must not.
        if (!from.via_path) return;
        LOCK(m_mutex);
        if (m_intros.size() >= PathTable::MAX_PATHS &&
            m_intros.find(service) == m_intros.end()) {
            return; // bounded, because registering is something strangers do
        }
        m_intros[service] = from.path;
        return;
    }

    case MessageKind::MEET: {
        roster::KeyBytes service;
        uint64_t meet_id = 0;
        if (!DecodeMeet(msg, service, meet_id)) return;
        if (!from.via_path) return;

        Hop service_hop;
        bool ok = false;
        {
            LOCK(m_mutex);
            std::map<roster::KeyBytes, uint64_t>::const_iterator it = m_intros.find(service);
            if (it != m_intros.end()) {
                service_hop = Hop::Path(it->second);
                m_paths.Expire(GetTime());
                // The splice: two paths joined, and this relay is the only
                // node that touches both. It still knows neither end's
                // address, because it reaches both of them through paths.
                ok = (service_hop != from) &&
                     m_paths.Create(meet_id, from, service_hop, GetTime());
            }
        }

        if (ok) {
            std::vector<unsigned char> bind;
            if (EncodePathBind(meet_id, bind)) SendToHop(service_hop, bind);
        }
        std::vector<unsigned char> reply;
        if (EncodePathResult(ok, meet_id, reply)) SendToHop(from, reply);
        return;
    }

    case MessageKind::PATH_DATA: {
        uint64_t path_id = 0;
        std::vector<unsigned char> inner;
        if (!DecodePathData(msg, path_id, inner)) return;

        Hop next;
        Route route;
        {
            LOCK(m_mutex);
            route = m_paths.Next(path_id, from, next, GetTime());
        }

        if (route == Route::FORWARD) {
            // Re-wrapped rather than passed through: each leg has its own
            // encryption, so the bytes arriving from one hop are never the
            // bytes leaving for the next.
            std::vector<unsigned char> out;
            if (!EncodePathData(path_id, inner, out)) return;
            SendToHop(next, out);
            return;
        }
        if (route != Route::DELIVER) return;

        // The end of the path. These bytes may be an end-to-end handshake or a
        // payload sealed for us, which the relays that carried them hold no key
        // for - or plain path traffic they could read.
        std::vector<unsigned char> reply, opened;
        PathTransport::Result r;
        {
            LOCK(m_mutex);
            r = m_secret.Receive(path_id, inner.data(), inner.size(), reply, opened);
        }
        if (!reply.empty()) SendOnPath(path_id, reply);

        switch (r) {
        case PathTransport::Result::PAYLOAD:
            // Sealed traffic from the far end. Dispatched rather than
            // delivered: this is how a relay is asked to extend a path, since
            // the asking arrives through the part already built.
            OnMessage(Hop::Path(path_id), std::move(opened));
            return;
        case PathTransport::Result::ESTABLISHED:
            LogPrint(BCLog::NET, "overlay: end-to-end session on path %016x\n", path_id);
            return;
        default:
            // Not end-to-end traffic, so it is plain path data for us -
            // readable by every relay that carried it, which is the difference
            // SendSecret exists to remove.
            if (m_app) m_app(from, std::move(inner));
            return;
        }
    }
    }
}

} // namespace overlay

// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/relay.h>

#include <logging.h>
#include <util/time.h>

namespace overlay {

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
        OnPayload(from, std::move(msg));
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

bool Relay::BuildPath(uint64_t path_id, const CService& via, const CService& dest)
{
    std::vector<unsigned char> msg;
    if (!EncodePathBuild(path_id, dest, msg)) return false;
    return m_socket.Send(via, msg);
}

bool Relay::SendVia(const CService& via, uint64_t path_id,
                    const std::vector<unsigned char>& inner)
{
    std::vector<unsigned char> msg;
    if (!EncodePathData(path_id, inner, msg)) return false;
    return m_socket.Send(via, msg);
}

bool Relay::ConnectSecret(const CService& via, uint64_t path_id,
                          const CPubKey& far_static)
{
    std::vector<unsigned char> hello;
    {
        LOCK(m_mutex);
        if (!m_secret.Connect(path_id, far_static, hello)) return false;
    }
    // The handshake rides the path as ordinary traffic. The relay forwards it
    // and cannot complete it: only the holder of far_static can.
    return SendVia(via, path_id, hello);
}

bool Relay::HasSecretSession(uint64_t path_id)
{
    LOCK(m_mutex);
    return m_secret.HasSession(path_id);
}

bool Relay::SendSecret(const CService& via, uint64_t path_id,
                       const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> sealed;
    {
        LOCK(m_mutex);
        if (!m_secret.Send(path_id, payload, sealed)) return false;
    }
    return SendVia(via, path_id, sealed);
}

size_t Relay::PathCount()
{
    LOCK(m_mutex);
    return m_paths.Size();
}

void Relay::OnPayload(const CService& from, std::vector<unsigned char>&& msg)
{
    MessageKind kind;
    // Unrecognised messages are dropped without a reply. The sender is
    // authenticated, so this is not an attack surface so much as a version
    // difference, and answering it tells an observer the two disagree.
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

        // Only join two peers already known here. Building a path to somewhere
        // this node has never spoken to would let a stranger use it to dial
        // arbitrary hosts, which is the property that separates an overlay
        // relay from an open proxy.
        bool ok = m_socket.HasSession(dest) && dest != from;
        if (ok) {
            LOCK(m_mutex);
            m_paths.Expire(GetTime());
            ok = m_paths.Create(path_id, from, dest, GetTime());
        }

        if (ok) {
            // Tell the far end it is this path's endpoint, or it would drop
            // everything forwarded to it having never asked for a path.
            std::vector<unsigned char> bind;
            if (EncodePathBind(path_id, bind)) m_socket.Send(dest, bind);
        }

        std::vector<unsigned char> reply;
        if (EncodePathResult(ok, path_id, reply)) m_socket.Send(from, reply);
        if (ok) {
            LogPrint(BCLog::NET, "overlay: path %016x joins %s and %s\n", path_id,
                     from.ToString(), dest.ToString());
        }
        return;
    }

    case MessageKind::PATH_OK:
    case MessageKind::PATH_FAIL: {
        bool ok = false;
        uint64_t path_id = 0;
        if (!DecodePathResult(msg, ok, path_id)) return;
        if (ok) {
            // The originator is an end of its own path too. Without an entry
            // here it sends fine and then drops every reply, because return
            // traffic arrives as PATH_DATA for a path it does not recognise.
            LOCK(m_mutex);
            m_paths.CreateEndpoint(path_id, from, GetTime());
        }
        if (m_path) m_path(path_id, ok);
        return;
    }

    case MessageKind::PATH_BIND: {
        uint64_t path_id = 0;
        if (!DecodePathBind(msg, path_id)) return;
        // Accepted only from a peer we already have a session with, which
        // Socket guarantees by delivering nothing else. Being made someone's
        // endpoint costs one table entry, bounded like any other.
        LOCK(m_mutex);
        m_paths.Expire(GetTime());
        m_paths.CreateEndpoint(path_id, from, GetTime());
        return;
    }

    case MessageKind::PATH_DATA: {
        uint64_t path_id = 0;
        std::vector<unsigned char> inner;
        if (!DecodePathData(msg, path_id, inner)) return;

        CService next;
        Route route;
        {
            LOCK(m_mutex);
            route = m_paths.Next(path_id, from, next, GetTime());
        }
        if (route == Route::DELIVER) {
            // The end of the path. The bytes may be an end-to-end handshake or
            // a sealed payload for us, in which case the relay that carried
            // them holds no key for them - or plain traffic it could read.
            std::vector<unsigned char> reply, opened;
            PathTransport::Result r;
            {
                LOCK(m_mutex);
                r = m_secret.Receive(path_id, inner.data(), inner.size(), reply, opened);
            }
            if (!reply.empty()) SendVia(from, path_id, reply);
            switch (r) {
            case PathTransport::Result::PAYLOAD:
                if (m_app) m_app(from, std::move(opened));
                return;
            case PathTransport::Result::ESTABLISHED:
                LogPrint(BCLog::NET, "overlay: end-to-end session on path %016x\n", path_id);
                return;
            default:
                // Not end-to-end traffic, so it is plain path data addressed
                // to us. Delivered as it stands, and readable by the relay -
                // which is the difference SendSecret exists to remove.
                if (m_app) m_app(from, std::move(inner));
                return;
            }
        }
        if (route != Route::FORWARD) return;

        // Re-wrapped rather than passed through: the outer session is per hop,
        // so the bytes that arrive from one peer are never the bytes that go to
        // the other.
        std::vector<unsigned char> out;
        if (!EncodePathData(path_id, inner, out)) return;
        m_socket.Send(next, out);
        return;
    }
    }
}

} // namespace overlay

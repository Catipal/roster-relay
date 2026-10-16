// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>

#include <limits> // FuzzedDataProvider.h uses it without including it

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

/*
 * What a gateway reads from strangers before anything else does: the
 * messages that arrive across a meeting, the pieces of fragmented packets,
 * and the packets themselves (design note §8·7). None of it may crash, read
 * out of bounds, or accept a packet that does not describe itself honestly.
 */
void test_one_input(const std::vector<uint8_t>& buffer)
{
    using namespace overlay;

    // As a packet: checked, then rewritten as the gateway rewrites it, then
    // checked again - a rewrite must never turn a packet into one that fails.
    PacketInfo info;
    std::string why;
    if (ParsePacket(buffer, info, why)) {
        assert(info.ip_header + info.l4_header + info.payload == buffer.size());
        std::vector<uint8_t> pkt = buffer;
        const IpAddr a = info.version == 6 ? IpAddr::V6({{0xfd, 0x62, 0x70, 0x73, 0x67, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}})
                                           : IpAddr::V4(100, 64, 0, 2);
        const IpAddr b = info.version == 6 ? IpAddr::V6({{0xfd, 0x62, 0x70, 0x73, 0x67, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
                                           : IpAddr::V4(100, 64, 0, 1);
        RewritePacket(pkt, info, a, 1024, b, 1);
        PacketInfo again;
        assert(ParsePacket(pkt, again, why));
        assert(again.src == a && again.dst == b && again.src_port == 1024 && again.dst_port == 1);
        assert(again.payload == info.payload && again.protocol == info.protocol);
        if (info.IsTcp()) {
            PacketInfo rst;
            assert(ParsePacket(BuildTcpReset(info), rst, why));
            assert(rst.src == info.dst && rst.dst == info.src);
        }
        (void)IsPublicAddress(info.dst);
    }

    // As a message, and as the pieces of a packet a stranger sends in turn.
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    Reassembler reassembler;
    int64_t now = 0;
    while (provider.remaining_bytes() > 0) {
        const std::vector<uint8_t> payload = provider.ConsumeBytes<uint8_t>(provider.ConsumeIntegralInRange<size_t>(0, 700));
        now += provider.ConsumeIntegralInRange<int64_t>(0, 4000);
        GatewayMessage m;
        if (!DecodeGatewayMessage(payload, m)) continue;
        if (m.kind == GatewayKind::FRAG) {
            std::vector<uint8_t> whole;
            if (reassembler.Add(provider.ConsumeIntegralInRange<uint64_t>(0, 3), m, now, whole)) {
                assert(!whole.empty() && whole.size() <= MAX_GATEWAY_PACKET);
            }
            assert(reassembler.PartialCount() <= 4 * Reassembler::MAX_PARTIAL);
        } else if (m.kind == GatewayKind::RESOLVE) {
            assert(IsResolvableName(m.name));
        }
    }
}

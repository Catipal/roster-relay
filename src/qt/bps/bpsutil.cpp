// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/bpsutil.h>

#include <qt/guiutil.h>

#include <univalue.h>

#include <QCoreApplication>

namespace BpsUtil {

QString HumanBlocks(int blocks)
{
    // Written out longhand rather than with Qt's %n plural form. Without a
    // translation loaded %n falls back to the source string, so "%n month(s)"
    // reaches the screen with the brackets still in it.
    const char* CTX = "BpsUtil";
    if (blocks <= 0) return QCoreApplication::translate(CTX, "less than a minute");

    const qint64 minutes = (qint64)blocks * SECONDS_PER_BLOCK / 60;
    if (minutes < 90) {
        if (minutes <= 1) return QCoreApplication::translate(CTX, "a minute");
        return QCoreApplication::translate(CTX, "%1 minutes").arg(minutes);
    }

    const qint64 hours = minutes / 60;
    if (hours < 48) {
        if (hours == 1) return QCoreApplication::translate(CTX, "an hour");
        return QCoreApplication::translate(CTX, "%1 hours").arg(hours);
    }

    const qint64 days = hours / 24;
    if (days < 60) return QCoreApplication::translate(CTX, "%1 days").arg(days);

    const qint64 months = days / 30;
    if (months < 12) {
        if (months == 1) return QCoreApplication::translate(CTX, "a month");
        return QCoreApplication::translate(CTX, "%1 months").arg(months);
    }
    if (months < 24) return QCoreApplication::translate(CTX, "about a year");
    return QCoreApplication::translate(CTX, "over a year");
}

QString ShortKey(const QString& hex)
{
    if (hex.size() <= 16) return hex;
    return hex.left(8) + QString::fromUtf8("\xe2\x80\xa6") + hex.right(6);
}

QString DescribeEndpoint(const UniValue& endpoint)
{
    if (!endpoint.isObject()) return QString();

    const UniValue& network = find_value(endpoint, "network");
    const UniValue& address = find_value(endpoint, "address");
    const UniValue& address_hex = find_value(endpoint, "address_hex");
    const UniValue& port = find_value(endpoint, "port");

    QString host;
    if (address.isStr()) {
        host = QString::fromStdString(address.get_str());
        // An IPv6 literal needs brackets before a port can be appended.
        if (host.contains(':')) host = "[" + host + "]";
    } else if (address_hex.isStr()) {
        // onion, i2p and cjdns arrive as raw bytes. Rendering the real textual
        // form means reimplementing each network's encoding, and getting one of
        // them subtly wrong would print an address that does not exist. The
        // network name plus a recognisable prefix is honest about what is known.
        const QString raw = QString::fromStdString(address_hex.get_str());
        host = (network.isStr() ? QString::fromStdString(network.get_str()) : QCoreApplication::translate("BpsUtil", "unknown"))
               + " " + raw.left(10) + QString::fromUtf8("\xe2\x80\xa6");
    } else {
        return QString();
    }

    if (port.isNum()) return host + ":" + QString::number(port.get_int());
    return host;
}

QFont FixedPitchFont()
{
    return GUIUtil::fixedPitchFont();
}

} // namespace BpsUtil

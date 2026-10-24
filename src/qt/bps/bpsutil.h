// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_BPSUTIL_H
#define BITCOIN_QT_BPS_BPSUTIL_H

#include <QFont>
#include <QString>
#include <QWidget>

class UniValue;

/**
 * Turning what the node says into what a person reads.
 *
 * The roster speaks in block heights and hex. Both are exact and neither is
 * legible, so everything on screen goes through here: heights become spans of
 * time, keys become a recognisable prefix with the whole of it on hover.
 */
namespace BpsUtil {

/** Block spacing, for turning a count of blocks into a span of time. */
static const int SECONDS_PER_BLOCK = 180;

/** "about 2 months", "11 days", "under an hour". Never a block count. */
QString HumanBlocks(int blocks);

/** The same, for a span given in seconds. */
QString HumanSeconds(qint64 seconds);

/** The first and last few characters of a key, enough to recognise one. */
QString ShortKey(const QString& hex);

/** One endpoint from a getroster reply, as "1.2.3.4:9345" or "onion:9346". */
QString DescribeEndpoint(const UniValue& endpoint);

/** The monospaced font the rest of the GUI uses, for keys and addresses. */
QFont FixedPitchFont();

/**
 * Scrolling a page with the wheel over a number box or a drop-down scrolls the
 * page, and changes nothing: only a box clicked into takes the wheel. Without
 * this, scrolling down the Server page turned whatever setting passed under
 * the pointer.
 */
void KeepWheelForPage(QWidget* page);

} // namespace BpsUtil

#endif // BITCOIN_QT_BPS_BPSUTIL_H

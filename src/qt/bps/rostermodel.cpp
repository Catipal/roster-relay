// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/rostermodel.h>

#include <qt/bps/bpsutil.h>

#include <univalue.h>

#include <QFont>

RosterModel::RosterModel(QObject* parent) : QAbstractTableModel(parent) {}

int RosterModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : m_rows.size();
}

int RosterModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant RosterModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
    switch (section) {
    case Peer: return tr("Peer");
    case Where: return tr("Address");
    case ListedAt: return tr("Listed");
    case Until: return tr("Listing ends");
    case History: return tr("Listed for");
    default: return QVariant();
    }
}

QVariant RosterModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= m_rows.size()) return QVariant();
    const RosterRow& row = m_rows.at(index.row());

    if (role == KeyRole) return row.key;
    if (role == AddressRole) return row.endpoints == 0 ? QString() : row.where;

    if (role == Qt::ToolTipRole) {
        switch (index.column()) {
        case Peer: return row.key + "\n" + tr("Click to copy");
        case Where:
            return row.endpoints == 0
                       ? tr("This peer is listed but publishes no address. It can still be\n"
                            "reached over the overlay, which is the point of allowing it.")
                       : (row.endpoints == 1 ? tr("one address published")
                                            : tr("%1 addresses published").arg(row.endpoints)) +
                             "\n" + tr("Click to copy");
        case ListedAt: return tr("Confirmed in block %1").arg(row.height);
        case Until: return tr("Stops counting at block %1").arg(row.expiry);
        case History: {
            // How long it has been listed without a break: the one thing a
            // newcomer cannot fake, and what entry relays are chosen by.
            QString text = row.since < 0 ? tr("No history before this listing.")
                                         : tr("Listed without a break since block %1.").arg(row.since);
            if (row.age == 0 && row.since >= 0) text += "\n" + tr("Too recent to count yet.");
            text += "\n" + (row.identity.isEmpty()
                                 ? tr("Not run under an identity.")
                                 : tr("Run under identity %1, which keeps its age if it changes keys.")
                                       .arg(BpsUtil::ShortKey(row.identity)));
            return text;
        }
        default: return QVariant();
        }
    }

    if (role == Qt::FontRole && index.column() == Peer) {
        return BpsUtil::FixedPitchFont();
    }

    if (role != Qt::DisplayRole) return QVariant();

    switch (index.column()) {
    case Peer:
        // In full: the view shortens it in the middle only when the column is
        // too narrow, so a wide window shows the whole key.
        return row.key;
    case Where:
        return row.endpoints == 0 ? tr("no address published") : row.where;
    case ListedAt: {
        const int age = m_tip - row.height;
        if (age <= 0) return tr("just now");
        return tr("%1 ago").arg(BpsUtil::HumanBlocks(age));
    }
    case Until: {
        const int left = row.expiry - m_tip;
        if (left <= 0) return tr("expired");
        return tr("in %1").arg(BpsUtil::HumanBlocks(left));
    }
    case History:
        return row.age > 0 ? BpsUtil::HumanBlocks(row.age) : tr("new");
    default:
        return QVariant();
    }
}

void RosterModel::SetTip(int tip)
{
    if (tip == m_tip) return;
    m_tip = tip;
    if (m_rows.isEmpty()) return;
    // Both time columns are relative to the tip, so both move when it does.
    Q_EMIT dataChanged(index(0, ListedAt), index(m_rows.size() - 1, Until));
}

void RosterModel::SetRoster(const UniValue& reply, int tip)
{
    QList<RosterRow> rows;
    if (reply.isArray()) {
        for (size_t i = 0; i < reply.size(); ++i) {
            const UniValue& entry = reply[i];
            if (!entry.isObject()) continue;

            RosterRow row;
            const UniValue& key = find_value(entry, "key");
            if (key.isStr()) row.key = QString::fromStdString(key.get_str());

            const UniValue& height = find_value(entry, "height");
            if (height.isNum()) row.height = height.get_int();
            const UniValue& expiry = find_value(entry, "expiry_height");
            if (expiry.isNum()) row.expiry = expiry.get_int();
            const UniValue& prev = find_value(entry, "prev_height");
            if (prev.isNum()) row.prev = prev.get_int();
            const UniValue& age = find_value(entry, "age_blocks");
            if (age.isNum()) row.age = age.get_int();
            const UniValue& since = find_value(entry, "since_height");
            if (since.isNum()) row.since = since.get_int();
            const UniValue& identity = find_value(entry, "identity");
            if (identity.isStr()) row.identity = QString::fromStdString(identity.get_str());

            const UniValue& eps = find_value(entry, "endpoints");
            if (eps.isArray()) {
                row.endpoints = (int)eps.size();
                if (eps.size() > 0) row.where = BpsUtil::DescribeEndpoint(eps[0]);
            }
            rows.append(row);
        }
    }

    beginResetModel();
    m_rows = rows;
    m_tip = tip;
    endResetModel();
}

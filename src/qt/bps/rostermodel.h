// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_ROSTERMODEL_H
#define BITCOIN_QT_BPS_ROSTERMODEL_H

#include <QAbstractTableModel>
#include <QList>
#include <QString>
#include <QStringList>

class UniValue;

/** One line of the roster, as getroster describes it. */
struct RosterRow {
    QString key;      //!< operational key, full hex
    QString where;    //!< first endpoint in readable form, or empty
    int endpoints{0}; //!< how many addresses the record carries
    int height{0};    //!< where the record confirmed
    int expiry{0};    //!< where it stops counting
    int prev{0};      //!< the previous record for this key, 0 when first
    int age{0};       //!< blocks of continuous history, 0 until it is deep enough to count
    int since{-1};    //!< where that history starts
    QString identity; //!< the identity running it, full hex, or empty
    bool relay{false};  //!< listed as a relay that announces its address while it runs
    QString announced;  //!< where it says it is now, readable, or empty when not heard from
    int announced_age{-1}; //!< seconds since it said so, -1 when not heard from
    QStringList meets;  //!< listed with no address: today's meeting points, full hex
    QString meet_point; //!< the meeting point its listing names, full hex, or empty
    QString note;       //!< the line of text its listing carries, or empty
};

/**
 * The live roster, for a table.
 *
 * Filled from the getroster reply rather than from RosterIndex, so the shape of
 * a roster entry is defined in one place. A field added to the RPC needs a
 * column here to be seen, but nothing here breaks when one is.
 */
class RosterModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        Peer = 0,
        Note,
        Where,
        ListedAt,
        Until,
        History,
        ColumnCount,
    };

    //! The full key of a row, for copying.
    static const int KeyRole = Qt::UserRole + 1;
    //! The address shown in a row, for copying; empty when none is published.
    static const int AddressRole = Qt::UserRole + 2;
    //! Whether a row is a relay that has said where it is in the last three hours.
    static const int OnlineRole = Qt::UserRole + 3;

    explicit RosterModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /** Replace the contents from a getroster reply. `tip` scales "expires in". */
    void SetRoster(const UniValue& reply, int tip);

    /** Re-render the "expires in" column when the chain moves. */
    void SetTip(int tip);

private:
    QList<RosterRow> m_rows;
    int m_tip{0};
};

#endif // BITCOIN_QT_BPS_ROSTERMODEL_H

// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_ROSTERMODEL_H
#define BITCOIN_QT_BPS_ROSTERMODEL_H

#include <QAbstractTableModel>
#include <QList>
#include <QString>

class UniValue;

/** One line of the roster, as getroster describes it. */
struct RosterRow {
    QString key;      //!< operational key, full hex
    QString where;    //!< first endpoint in readable form, or empty
    int endpoints{0}; //!< how many addresses the record carries
    int height{0};    //!< where the record confirmed
    int expiry{0};    //!< where it stops counting
    int prev{0};      //!< the previous record for this key, 0 when first
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
        Where,
        ListedAt,
        Until,
        History,
        ColumnCount,
    };

    //! The full key of a row, for copying. Rows show a shortened form.
    static const int KeyRole = Qt::UserRole + 1;

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

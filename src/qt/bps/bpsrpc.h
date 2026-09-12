// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_BPSRPC_H
#define BITCOIN_QT_BPS_BPSRPC_H

#include <univalue.h>

#include <QMetaType>
#include <QObject>
#include <QString>
#include <QThread>

namespace interfaces {
class Node;
} // namespace interfaces

Q_DECLARE_METATYPE(UniValue)

/**
 * How this client talks to the node it is running.
 *
 * Everything the discovery pages need already exists as an RPC: getrosterinfo,
 * getroster, getoverlayinfo, createannouncement, publishrecord. Calling those
 * rather than reaching into RosterIndex and the overlay globals directly is the
 * decision that keeps the two clients from drifting apart. The core layer owns
 * the answers; this client only asks. When a roster field is added below, it
 * arrives here without a line changing in the GUI.
 *
 * It is an in-process call - the same one qt/rpcconsole.cpp makes - not an HTTP
 * request, so there is no port to open, no credentials, and nothing to
 * configure. The only cost is that it can block: BuildRoster scans a year of
 * blocks, which is not something to do on the thread painting the window. Hence
 * the worker below.
 */
class BpsRpcWorker : public QObject
{
    Q_OBJECT

public:
    explicit BpsRpcWorker(interfaces::Node& node) : m_node(node) {}

public Q_SLOTS:
    void execute(const QString& tag, const QString& method, const UniValue& params, const QString& uri);

Q_SIGNALS:
    void result(const QString& tag, const UniValue& value);
    void failed(const QString& tag, const QString& message);

private:
    interfaces::Node& m_node;
};

/**
 * A queue of RPC calls, answered on a thread of its own.
 *
 * Calls carry a `tag` that comes back with the answer, so one page can have
 * several in flight and still tell them apart. Answers arrive as signals on the
 * GUI thread; a call that throws arrives as failed() rather than as an
 * exception, because a JSON-RPC error here is an ordinary state - the index is
 * off, the wallet is locked - not a fault.
 */
class BpsRpc : public QObject
{
    Q_OBJECT

public:
    explicit BpsRpc(interfaces::Node& node, QObject* parent = nullptr);
    ~BpsRpc();

    /** Queue one call. Returns immediately; watch result() and failed(). */
    void Call(const QString& tag, const QString& method,
              const UniValue& params = UniValue(UniValue::VARR),
              const QString& uri = QString());

Q_SIGNALS:
    void result(const QString& tag, const UniValue& value);
    void failed(const QString& tag, const QString& message);

    //! Internal: hands the call to the worker thread.
    void request(const QString& tag, const QString& method, const UniValue& params, const QString& uri);

private:
    QThread m_thread;
};

#endif // BITCOIN_QT_BPS_BPSRPC_H

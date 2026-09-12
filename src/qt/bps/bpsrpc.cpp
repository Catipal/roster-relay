// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/bpsrpc.h>

#include <interfaces/node.h>

#include <exception>

void BpsRpcWorker::execute(const QString& tag, const QString& method,
                           const UniValue& params, const QString& uri)
{
    try {
        const UniValue out = m_node.executeRpc(method.toStdString(), params, uri.toStdString());
        Q_EMIT result(tag, out);
    } catch (const UniValue& e) {
        // A JSON-RPC error object. The message is the part worth showing; the
        // code is for callers that need to distinguish, and none here do.
        const UniValue& msg = find_value(e, "message");
        Q_EMIT failed(tag, msg.isStr() ? QString::fromStdString(msg.get_str())
                                       : QString::fromStdString(e.write()));
    } catch (const std::exception& e) {
        Q_EMIT failed(tag, QString::fromStdString(e.what()));
    } catch (...) {
        Q_EMIT failed(tag, tr("Unknown error"));
    }
}

BpsRpc::BpsRpc(interfaces::Node& node, QObject* parent) : QObject(parent)
{
    // UniValue crosses a thread boundary in the signals below, so Qt has to be
    // told how to copy it.
    qRegisterMetaType<UniValue>("UniValue");

    BpsRpcWorker* worker = new BpsRpcWorker(node);
    worker->moveToThread(&m_thread);

    connect(&m_thread, &QThread::finished, worker, &QObject::deleteLater);
    connect(this, &BpsRpc::request, worker, &BpsRpcWorker::execute);
    connect(worker, &BpsRpcWorker::result, this, &BpsRpc::result);
    connect(worker, &BpsRpcWorker::failed, this, &BpsRpc::failed);

    m_thread.start();
}

BpsRpc::~BpsRpc()
{
    m_thread.quit();
    m_thread.wait();
}

void BpsRpc::Call(const QString& tag, const QString& method, const UniValue& params, const QString& uri)
{
    Q_EMIT request(tag, method, params, uri);
}

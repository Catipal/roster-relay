// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_APP_BACKEND_H
#define BPS_MOBILE_APP_BACKEND_H

#include <companion/client.h>
#include <companion/protocol.h>
#include <key.h>

#include <QObject>
#include <QString>
#include <QThread>
#include <QVariantList>
#include <QVariantMap>

#include <functional>
#include <memory>

/**
 * What the screens see of the companion: one home node, its answers, and
 * whether a question is out. Every exchange with the home node can take
 * seconds - a path of three relays is built first when none is open - so the
 * client lives on a thread of its own and the screens only read properties
 * and call the slots below, which return at once.
 *
 * What it keeps between runs, in the app's data folder: the device key and
 * home.json, the home node as the client remembers it. A payment prepared
 * but not sent is kept in memory only: the home node forgets it on a restart
 * too.
 */
class Backend : public QObject
{
    Q_OBJECT
    /** "unpaired", "waiting" (to be accepted on the home node), "paired" or "locked". */
    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString error READ error NOTIFY errorChanged)
    Q_PROPERTY(QString pairingCode READ pairingCode NOTIFY stateChanged)
    Q_PROPERTY(QString phoneName READ phoneName NOTIFY stateChanged)
    Q_PROPERTY(QString homeNode READ homeNode NOTIFY stateChanged)
    Q_PROPERTY(QString network READ network NOTIFY stateChanged)
    Q_PROPERTY(int relaysKnown READ relaysKnown NOTIFY stateChanged)
    Q_PROPERTY(QVariantMap status READ status NOTIFY statusChanged)
    Q_PROPERTY(QVariantList history READ history NOTIFY historyChanged)
    Q_PROPERTY(QString address READ address NOTIFY addressChanged)
    Q_PROPERTY(QVariantMap prepared READ prepared NOTIFY preparedChanged)
    Q_PROPERTY(QVariantMap sent READ sent NOTIFY sentChanged)

public:
    explicit Backend(const QString& data_dir, QObject* parent = nullptr);
    ~Backend() override;

    /** Read the device key and home.json; false and `error` if the key is damaged. */
    bool Load(QString& error);

    QString state() const { return m_state; }
    bool busy() const { return m_busy; }
    QString error() const { return m_error; }
    QString pairingCode() const;
    QString phoneName() const { return m_name; }
    QString homeNode() const;
    QString network() const { return QString::fromStdString(m_home.network); }
    int relaysKnown() const { return int(m_home.relays.size()); }
    QVariantMap status() const { return m_status; }
    QVariantList history() const { return m_history; }
    QString address() const { return m_address; }
    QVariantMap prepared() const { return m_prepared_view; }
    QVariantMap sent() const { return m_sent; }

    /** Whether a pasted ticket reads as one: "" if so, else what is wrong. */
    Q_INVOKABLE QString checkTicket(const QString& text) const;
    Q_INVOKABLE bool validPin(const QString& pin) const;
    /** Whether `text` is an amount above zero. */
    Q_INVOKABLE bool validAmount(const QString& text) const;
    Q_INVOKABLE void copyText(const QString& text) const;

public Q_SLOTS:
    void pair(const QString& ticket, const QString& name, const QString& pin);
    /** Ask whether the home node has accepted yet; quiet while a question is out. */
    void pollPairing();
    /** Status and the latest payments. */
    void refresh();
    void loadHistory();
    void newAddress();
    void prepare(const QString& to, const QString& amount);
    void send(const QString& pin);
    void cancel();
    void unpair();
    /** Forget the home node here, whatever the home node thinks. */
    void forget();
    void clearError();

Q_SIGNALS:
    void stateChanged();
    void busyChanged();
    void errorChanged();
    void statusChanged();
    void historyChanged();
    void addressChanged();
    void preparedChanged();
    void sentChanged();
    /** A payment was prepared and is waiting for the PIN. */
    void preparedReady();
    void sendDone();

private:
    /** Run `work` on the client's thread; `done` back on this one with its result. */
    void Run(std::function<bool(companion::Client&, std::string&)> work, std::function<void()> done,
             std::function<void(const QString&)> failed = nullptr);
    void SetBusy(bool busy);
    void SetError(const QString& error);
    void SetState(const QString& state);
    void Save();
    void ApplyStatus(const companion::StatusAnswer& a);
    void ApplyHistory(const std::vector<companion::HistoryItem>& items);

    const QString m_dir;
    CKey m_device;

    QThread m_thread;
    QObject* m_worker; //!< lives on m_thread; the client is only touched from there
    std::unique_ptr<companion::Client> m_client; //!< worker thread only
    std::string m_client_home; //!< which home m_client was set up for (worker thread only)

    QString m_state{QStringLiteral("unpaired")};
    bool m_busy{false};
    int m_pending{0}; //!< questions sent to the worker and not yet answered
    QString m_error;
    QString m_name;
    companion::Home m_home;
    uint256 m_token;
    QVariantMap m_status;
    QVariantList m_history;
    QString m_address;
    bool m_has_prepared{false};
    companion::PrepareAnswer m_prepared;
    QVariantMap m_prepared_view;
    QVariantMap m_sent;
};

#endif // BPS_MOBILE_APP_BACKEND_H

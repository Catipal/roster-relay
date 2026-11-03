// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <backend.h>

#include <pubkey.h>
#include <util/moneystr.h>
#include <util/strencodings.h>

#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QSaveFile>

#include <algorithm>

using namespace companion;

namespace {

QString Q(const std::string& s) { return QString::fromStdString(s); }

QString Coins(CAmount amount) { return Q(FormatMoney(amount)); }

/**
 * The device key, made here on first run. Kept as hex in a file only this
 * user can read - encrypted at rest once a keystore is linked; until then the
 * phone's own storage protection is all it has. It can spend nothing by
 * itself: the home node also wants the PIN.
 */
bool LoadOrMakeDeviceKey(const QString& path, CKey& key)
{
    QFile in(path);
    if (in.open(QIODevice::ReadOnly)) {
        const std::vector<unsigned char> raw = ParseHex(in.readAll().trimmed().toStdString());
        if (raw.size() != 32) return false;
        key.Set(raw.begin(), raw.end(), true);
        return key.IsValid();
    }
    key.MakeNewKey(true);
    QSaveFile out(path);
    if (!out.open(QIODevice::WriteOnly)) return false;
    out.write(QByteArray::fromStdString(HexStr(Span<const unsigned char>(key.begin(), key.size())) + "\n"));
    if (!out.commit()) return false;
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

} // namespace

Backend::Backend(const QString& data_dir, QObject* parent)
    : QObject(parent), m_dir(data_dir), m_worker(new QObject)
{
    m_thread.setObjectName(QStringLiteral("companion"));
    m_worker->moveToThread(&m_thread);
    connect(&m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    m_thread.start();
}

Backend::~Backend()
{
    // The client goes on the thread it was used on, before the thread does.
    QMetaObject::invokeMethod(m_worker, [this] {
        if (m_client) m_client->Stop();
        m_client.reset();
    }, Qt::BlockingQueuedConnection);
    m_thread.quit();
    m_thread.wait();
}

bool Backend::Load(QString& error)
{
    QDir().mkpath(m_dir);
    if (!LoadOrMakeDeviceKey(m_dir + QStringLiteral("/device.key"), m_device)) {
        error = tr("The device key in %1 is damaged.").arg(m_dir);
        return false;
    }
    QFile in(m_dir + QStringLiteral("/home.json"));
    if (!in.open(QIODevice::ReadOnly)) return true;
    const QJsonObject v = QJsonDocument::fromJson(in.readAll()).object();
    if (v.isEmpty()) return true;
    m_home.network = v.value(QStringLiteral("network")).toString().toStdString();
    m_home.node = CPubKey(ParseHex(v.value(QStringLiteral("node")).toString().toStdString()));
    m_home.node_addr = v.value(QStringLiteral("node_addr")).toString().toStdString();
    for (const QJsonValue& e : v.value(QStringLiteral("relays")).toArray()) {
        const QJsonArray pair = e.toArray();
        RelayEntry r;
        r.key = CPubKey(ParseHex(pair.at(0).toString().toStdString()));
        r.addr = pair.at(1).toString().toStdString();
        m_home.relays.push_back(r);
    }
    m_name = v.value(QStringLiteral("name")).toString();
    const QString token = v.value(QStringLiteral("token")).toString();
    if (!token.isEmpty()) m_token = uint256S(token.toStdString());
    if (!m_home.node.IsFullyValid()) {
        m_home = Home();
        return true;
    }
    m_state = m_token.IsNull() ? QStringLiteral("paired") : QStringLiteral("waiting");
    return true;
}

void Backend::Save()
{
    const QString path = m_dir + QStringLiteral("/home.json");
    if (m_state == QLatin1String("unpaired")) {
        QFile::remove(path);
        return;
    }
    QJsonObject v;
    v.insert(QStringLiteral("network"), Q(m_home.network));
    v.insert(QStringLiteral("node"), Q(HexStr(m_home.node)));
    v.insert(QStringLiteral("node_addr"), Q(m_home.node_addr));
    QJsonArray relays;
    for (const RelayEntry& r : m_home.relays) relays.append(QJsonArray{Q(HexStr(r.key)), Q(r.addr)});
    v.insert(QStringLiteral("relays"), relays);
    v.insert(QStringLiteral("name"), m_name);
    if (!m_token.IsNull()) v.insert(QStringLiteral("token"), Q(m_token.GetHex()));
    QSaveFile out(path);
    if (out.open(QIODevice::WriteOnly)) {
        out.write(QJsonDocument(v).toJson());
        out.commit();
    }
}

QString Backend::pairingCode() const
{
    if (m_token.IsNull() || !m_home.node.IsValid()) return {};
    const QString code = Q(PairingCode(m_token, m_device.GetPubKey(), m_home.node));
    return code.left(3) + QLatin1Char(' ') + code.mid(3);
}

QString Backend::homeNode() const
{
    if (!m_home.node.IsValid()) return {};
    const QString hex = Q(HexStr(m_home.node));
    return hex.left(8) + QStringLiteral("…") + hex.right(7);
}

QString Backend::checkTicket(const QString& text) const
{
    PairingTicket t;
    std::string error;
    if (!DecodeTicket(text.trimmed().toStdString(), t, error)) return Q(error);
    return {};
}

bool Backend::validPin(const QString& pin) const { return ValidPin(pin.toStdString()); }

bool Backend::validAmount(const QString& text) const
{
    CAmount amount;
    return ParseMoney(text.trimmed().toStdString(), amount) && amount > 0;
}

void Backend::copyText(const QString& text) const { QGuiApplication::clipboard()->setText(text); }

void Backend::SetBusy(bool busy)
{
    if (m_busy == busy) return;
    m_busy = busy;
    Q_EMIT busyChanged();
}

void Backend::SetError(const QString& error)
{
    if (m_error == error) return;
    m_error = error;
    Q_EMIT errorChanged();
}

void Backend::clearError() { SetError({}); }

void Backend::SetState(const QString& state)
{
    m_state = state;
    Save();
    Q_EMIT stateChanged();
}

void Backend::Run(std::function<bool(Client&, std::string&)> work, std::function<void()> done,
                  std::function<void(const QString&)> failed)
{
    // Questions queue on the one thread and are answered in turn.
    ++m_pending;
    SetBusy(true);
    SetError({});
    const Home home = m_home;
    const CKey device = m_device;
    QMetaObject::invokeMethod(m_worker, [this, home, device, work, done, failed] {
        std::string error;
        bool ok = false;
        // One client per home node, kept while the app runs so an open path
        // is used again rather than built anew for every question.
        const std::string id = HexStr(home.node) + home.network;
        if (!m_client || m_client_home != id) {
            if (m_client) m_client->Stop();
            m_client = std::make_unique<Client>(device, home.network == "regtest");
            m_client_home = id;
            if (!m_client->Start(error)) {
                m_client.reset();
                m_client_home.clear();
            }
        }
        if (m_client) {
            m_client->SetHome(home);
            try {
                ok = work(*m_client, error);
            } catch (const std::exception& e) {
                error = e.what();
            }
        }
        QMetaObject::invokeMethod(this, [this, ok, error, done, failed] {
            SetBusy(--m_pending > 0);
            if (ok) {
                if (done) done();
            } else if (failed) {
                failed(Q(error));
            } else {
                SetError(Q(error));
            }
        });
    });
}

void Backend::pair(const QString& ticket, const QString& name, const QString& pin)
{
    PairingTicket t;
    std::string error;
    if (!DecodeTicket(ticket.trimmed().toStdString(), t, error)) return SetError(Q(error));
    if (!ValidPin(pin.toStdString())) return SetError(tr("A PIN is six to twelve digits."));
    const std::string device_name = name.trimmed().toStdString();
    const std::string pin_text = pin.toStdString();
    m_home = Home();
    m_home.network = t.network;
    m_home.node = t.node;
    m_home.node_addr = t.node_addr;
    m_home.relays = t.relays;
    m_token = t.token;
    m_name = name.trimmed();
    const uint256 token = t.token;
    Run([token, device_name, pin_text](Client& c, std::string& e) { return c.Pair(token, device_name, pin_text, e); },
        [this] { SetState(QStringLiteral("waiting")); },
        [this](const QString& e) {
            m_home = Home();
            m_token.SetNull();
            SetError(e);
            SetState(QStringLiteral("unpaired"));
        });
}

void Backend::pollPairing()
{
    if (m_busy || m_state != QLatin1String("waiting")) return;
    auto answer = std::make_shared<PairStateAnswer>();
    auto home = std::make_shared<Home>();
    const uint256 token = m_token;
    Run(
        [token, answer, home](Client& c, std::string& e) {
            if (!c.PairStatus(token, *answer, e)) return false;
            if (answer->state == uint8_t(PairState::ACCEPTED)) {
                // Paired: learn the home node's current relays while the path is open.
                std::string ignored;
                c.RefreshRelays(ignored);
                *home = c.GetHome();
            }
            return true;
        },
        [this, answer, home] {
            switch (PairState(answer->state)) {
            case PairState::WAITING:
                return;
            case PairState::ACCEPTED:
                if (!home->relays.empty()) m_home.relays = home->relays;
                m_token.SetNull();
                SetState(QStringLiteral("paired"));
                refresh();
                return;
            case PairState::REJECTED:
                SetError(tr("The home node rejected this phone."));
                break;
            default:
                SetError(tr("The pairing code expired before it was accepted. Show a new one on the home node."));
                break;
            }
            m_home = Home();
            m_token.SetNull();
            SetState(QStringLiteral("unpaired"));
        },
        // Unreachable for now: try again on the next poll, and say why meanwhile.
        [this](const QString& e) { SetError(e); });
}

void Backend::ApplyStatus(const StatusAnswer& a)
{
    m_status = QVariantMap{
        {QStringLiteral("balance"), Coins(a.balance)},
        {QStringLiteral("pending"), Coins(a.pending)},
        {QStringLiteral("hasPending"), a.pending != 0},
        {QStringLiteral("perTx"), Coins(a.per_tx)},
        {QStringLiteral("perDay"), Coins(a.per_day)},
        {QStringLiteral("spentToday"), Coins(a.spent_today)},
        {QStringLiteral("leftToday"), Coins(std::max<CAmount>(0, a.per_day - a.spent_today))},
        {QStringLiteral("leftFraction"),
         a.per_day > 0 ? double(std::max<CAmount>(0, a.per_day - a.spent_today)) / double(a.per_day) : 0.0},
        {QStringLiteral("height"), a.height},
        {QStringLiteral("reached"), QLocale().toString(QTime::currentTime(), QLocale::ShortFormat)},
    };
    Q_EMIT statusChanged();
    const QString state = a.locked ? QStringLiteral("locked") : QStringLiteral("paired");
    if (state != m_state) SetState(state);
}

void Backend::ApplyHistory(const std::vector<HistoryItem>& items)
{
    QVariantList list;
    for (const HistoryItem& i : items) {
        const bool in = i.amount > 0;
        QString label;
        if (in) {
            label = tr("Received");
        } else if (!i.counterparty.empty()) {
            label = tr("To %1").arg(Q(i.counterparty));
        } else {
            label = tr("Sent");
        }
        const QDateTime when = QDateTime::fromSecsSinceEpoch(i.time);
        QString time = QLocale().toString(when, QLocale::ShortFormat);
        if (i.confirmations <= 0) time = tr("%1, not yet confirmed").arg(time);
        list.append(QVariantMap{
            {QStringLiteral("label"), label},
            {QStringLiteral("when"), time},
            {QStringLiteral("signed"), (in ? QStringLiteral("+") : QString()) + Coins(i.amount)},
            {QStringLiteral("incoming"), in},
            {QStringLiteral("txid"), Q(i.txid.GetHex())},
        });
    }
    m_history = list;
    Q_EMIT historyChanged();
}

void Backend::refresh()
{
    if (m_state != QLatin1String("paired") && m_state != QLatin1String("locked")) return;
    auto status = std::make_shared<StatusAnswer>();
    auto items = std::make_shared<std::vector<HistoryItem>>();
    Run(
        [status, items](Client& c, std::string& e) {
            return c.Status(*status, e) && c.History(0, MAX_HISTORY, *items, e);
        },
        [this, status, items] {
            ApplyStatus(*status);
            ApplyHistory(*items);
        });
}

void Backend::loadHistory()
{
    auto items = std::make_shared<std::vector<HistoryItem>>();
    Run([items](Client& c, std::string& e) { return c.History(0, MAX_HISTORY, *items, e); },
        [this, items] { ApplyHistory(*items); });
}

void Backend::newAddress()
{
    auto address = std::make_shared<std::string>();
    Run([address](Client& c, std::string& e) { return c.Address(*address, e); },
        [this, address] {
            m_address = Q(*address);
            Q_EMIT addressChanged();
        });
}

void Backend::prepare(const QString& to, const QString& amount_text)
{
    CAmount amount;
    if (!ParseMoney(amount_text.trimmed().toStdString(), amount) || amount <= 0) {
        return SetError(tr("That is not an amount."));
    }
    const std::string payee = to.trimmed().toStdString();
    if (payee.empty()) return SetError(tr("Who is it for? An address or a name."));
    auto p = std::make_shared<PrepareAnswer>();
    const QString shown = to.trimmed();
    Run([payee, amount, p](Client& c, std::string& e) { return c.Prepare(payee, amount, false, *p, e); },
        [this, p, shown] {
            m_prepared = *p;
            m_has_prepared = true;
            const QString address = Q(p->payee);
            m_prepared_view = QVariantMap{
                {QStringLiteral("to"), shown},
                {QStringLiteral("address"), address},
                {QStringLiteral("isName"), shown != address},
                {QStringLiteral("amount"), Coins(p->amount)},
                {QStringLiteral("fee"), Coins(p->fee)},
                {QStringLiteral("total"), Coins(p->amount + p->fee)},
            };
            Q_EMIT preparedChanged();
            Q_EMIT preparedReady();
        });
}

void Backend::send(const QString& pin)
{
    if (!m_has_prepared) return SetError(tr("Nothing is prepared. Review the payment again."));
    const PrepareAnswer p = m_prepared;
    const std::string pin_text = pin.toStdString();
    auto txid = std::make_shared<uint256>();
    auto status = std::make_shared<StatusAnswer>();
    auto have_status = std::make_shared<bool>(false);
    Run(
        [p, pin_text, txid, status, have_status](Client& c, std::string& e) {
            if (c.Send(p, pin_text, *txid, e)) return true;
            // A wrong PIN may have locked it: ask, so the screen can say so.
            std::string ignored;
            *have_status = c.Status(*status, ignored);
            return false;
        },
        [this, p, txid] {
            m_has_prepared = false;
            m_sent = QVariantMap{
                {QStringLiteral("to"), m_prepared_view.value(QStringLiteral("to"))},
                {QStringLiteral("amount"), Coins(p.amount)},
                {QStringLiteral("txid"), Q(txid->GetHex())},
            };
            Q_EMIT sentChanged();
            Q_EMIT sendDone();
            refresh();
        },
        [this, status, have_status](const QString& e) {
            SetError(e);
            if (*have_status) ApplyStatus(*status);
        });
}

void Backend::cancel()
{
    if (!m_has_prepared) return;
    m_has_prepared = false;
    const uint256 id = m_prepared.prepare_id;
    // The home node lets it go by itself when it expires; telling it is a courtesy.
    Run([id](Client& c, std::string& e) { return c.Cancel(id, e); }, nullptr, [](const QString&) {});
}

void Backend::unpair()
{
    Run([](Client& c, std::string& e) { return c.Unpair(e); }, [this] { forget(); });
}

void Backend::forget()
{
    m_home = Home();
    m_token.SetNull();
    m_status.clear();
    m_history.clear();
    m_address.clear();
    m_has_prepared = false;
    Q_EMIT statusChanged();
    Q_EMIT historyChanged();
    Q_EMIT addressChanged();
    SetState(QStringLiteral("unpaired"));
}

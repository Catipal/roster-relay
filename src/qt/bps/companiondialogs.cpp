// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h> /* for USE_QRCODE */
#endif

#include <qt/bps/companiondialogs.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bitcoinamountfield.h>
#include <qt/guiutil.h>

#include <core_io.h>
#include <univalue.h>
#include <util/moneystr.h>

#include <algorithm>
#include <cmath>

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QImage>
#include <QLabel>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

namespace {

const char* TAG_TICKET = "companionpair:ticket";
const char* TAG_PENDING = "companionpair:pending";
const char* TAG_ACCEPT = "companionpair:accept";
const char* TAG_REJECT = "companionpair:reject";

/** Pixels a QR code is drawn at, at least: big enough to scan from across a desk. */
const int QR_SIZE = 380;

/**
 * A QR code of `text`, drawn module by module so it stays sharp at any size.
 * Not QRImageWidget: that one stops at the length of a payment URI, and a
 * ticket is longer.
 */
QPixmap MakeQR(const QString& text)
{
#ifdef USE_QRCODE
    QRcode* code = QRcode_encodeString(text.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!code) return QPixmap();
    const int quiet = 4;
    QImage image(code->width + 2 * quiet, code->width + 2 * quiet, QImage::Format_RGB32);
    image.fill(0xffffff);
    const unsigned char* p = code->data;
    for (int y = 0; y < code->width; ++y) {
        for (int x = 0; x < code->width; ++x, ++p) {
            if (*p & 1) image.setPixel(x + quiet, y + quiet, 0x0);
        }
    }
    QRcode_free(code);
    // A whole number of the screen's own pixels to every module: scaled by a
    // fraction - here or by Windows' display scaling - some modules come out
    // a pixel wider than others, which a camera reading a dense code off a
    // screen trips on.
    const qreal dpr = std::max<qreal>(1.0, qApp->devicePixelRatio());
    const int scale = std::max(3, int(std::ceil(QR_SIZE * dpr / image.width())));
    QPixmap pixmap = QPixmap::fromImage(image.scaled(image.width() * scale, image.height() * scale, Qt::KeepAspectRatio, Qt::FastTransformation));
    pixmap.setDevicePixelRatio(dpr);
    return pixmap;
#else
    Q_UNUSED(text);
    return QPixmap();
#endif
}

QString Spaced(const QString& code)
{
    return code.size() == 6 ? code.left(3) + " " + code.mid(3) : code;
}

CAmount AmountOf(const BitcoinAmountField* field, bool& valid)
{
    valid = false;
    const CAmount v = field->value(&valid);
    if (v <= 0) valid = false;
    return v;
}

QString LimitsProblem(bool tx_ok, CAmount per_tx, bool day_ok, CAmount per_day)
{
    if (!tx_ok || !day_ok) return QObject::tr("Set both limits.");
    if (per_tx > per_day) return QObject::tr("One payment cannot be allowed more than a whole day.");
    return QString();
}

} // namespace

CompanionPairDialog::CompanionPairDialog(BpsRpc& rpc, QWidget* parent) : QDialog(parent), m_rpc(rpc)
{
    setWindowTitle(tr("Pair a phone"));
    QVBoxLayout* outer = new QVBoxLayout(this);
    m_steps = new QStackedWidget(this);
    outer->addWidget(m_steps);

    // 1. The ticket.
    QWidget* ticket_page = new QWidget(m_steps);
    QVBoxLayout* t = new QVBoxLayout(ticket_page);
    QLabel* intro = new QLabel(tr("In the BPS app on the phone, choose Pair and scan this code. Or copy the text "
                                  "under it into the app. It works once, for ten minutes."),
                               ticket_page);
    intro->setWordWrap(true);
    t->addWidget(intro);
    m_qr = new QLabel(ticket_page);
    m_qr->setAlignment(Qt::AlignCenter);
    m_qr->setMinimumSize(QR_SIZE, QR_SIZE);
    t->addWidget(m_qr);
    m_ticket = new QPlainTextEdit(ticket_page);
    m_ticket->setReadOnly(true);
    m_ticket->setFont(GUIUtil::fixedPitchFont());
    m_ticket->setMaximumHeight(90);
    t->addWidget(m_ticket);
    QHBoxLayout* row = new QHBoxLayout();
    QPushButton* copy = new QPushButton(tr("Copy the code"), ticket_page);
    connect(copy, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(m_ticket->toPlainText()); });
    row->addWidget(copy);
    row->addStretch(1);
    m_again = new QPushButton(tr("Show a new code"), ticket_page);
    m_again->setVisible(false);
    connect(m_again, &QPushButton::clicked, this, &CompanionPairDialog::NewTicket);
    row->addWidget(m_again);
    t->addLayout(row);
    m_wait = new QLabel(ticket_page);
    m_wait->setWordWrap(true);
    t->addWidget(m_wait);
    m_steps->addWidget(ticket_page);

    // 2. A phone answered it.
    QWidget* answered = new QWidget(m_steps);
    QVBoxLayout* a = new QVBoxLayout(answered);
    m_who = new QLabel(answered);
    m_who->setWordWrap(true);
    // The name is the phone's to choose: shown as written, never as markup.
    m_who->setTextFormat(Qt::PlainText);
    a->addWidget(m_who);
    m_code = new QLabel(answered);
    QFont code_font = GUIUtil::fixedPitchFont();
    code_font.setPointSizeF(code_font.pointSizeF() * 2.4);
    code_font.setBold(true);
    m_code->setFont(code_font);
    m_code->setAlignment(Qt::AlignCenter);
    a->addWidget(m_code);
    QLabel* check = new QLabel(tr("Pair only if the phone shows these same six digits. If it shows others, someone "
                                  "else answered the code first: reject, and show a new one."),
                               answered);
    check->setWordWrap(true);
    a->addWidget(check);
    QLabel* limits_text = new QLabel(tr("What this phone may spend from the allowance wallet. Only this node can "
                                        "change it later, never the phone."),
                                     answered);
    limits_text->setWordWrap(true);
    a->addWidget(limits_text);
    QFormLayout* form = new QFormLayout();
    m_per_tx = new BitcoinAmountField(answered);
    m_per_day = new BitcoinAmountField(answered);
    form->addRow(tr("Most in one payment"), m_per_tx);
    form->addRow(tr("Most in any 24 hours"), m_per_day);
    a->addLayout(form);
    m_error = new QLabel(answered);
    m_error->setWordWrap(true);
    a->addWidget(m_error);
    QHBoxLayout* buttons = new QHBoxLayout();
    buttons->addStretch(1);
    m_reject = new QPushButton(tr("Reject"), answered);
    m_accept = new QPushButton(tr("Pair this phone"), answered);
    m_accept->setDefault(true);
    m_accept->setEnabled(false);
    buttons->addWidget(m_reject);
    buttons->addWidget(m_accept);
    a->addLayout(buttons);
    connect(m_per_tx, &BitcoinAmountField::valueChanged, this, &CompanionPairDialog::UpdateAcceptable);
    connect(m_per_day, &BitcoinAmountField::valueChanged, this, &CompanionPairDialog::UpdateAcceptable);
    connect(m_accept, &QPushButton::clicked, this, &CompanionPairDialog::Accept);
    connect(m_reject, &QPushButton::clicked, this, &CompanionPairDialog::Reject);
    m_steps->addWidget(answered);

    // 3. Paired.
    QWidget* done = new QWidget(m_steps);
    QVBoxLayout* d = new QVBoxLayout(done);
    m_done = new QLabel(done);
    m_done->setWordWrap(true);
    d->addWidget(m_done);
    d->addStretch(1);
    m_steps->addWidget(done);

    QDialogButtonBox* close = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(close, &QDialogButtonBox::rejected, this, &QDialog::reject);
    outer->addWidget(close);

    connect(&m_rpc, &BpsRpc::result, this, &CompanionPairDialog::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &CompanionPairDialog::onRpcFailed);
    m_timer = new QTimer(this);
    m_timer->setInterval(2000);
    connect(m_timer, &QTimer::timeout, this, &CompanionPairDialog::Poll);

    NewTicket();
}

void CompanionPairDialog::NewTicket()
{
    m_answered = false;
    m_token.clear();
    m_again->setVisible(false);
    m_wait->setText(tr("Making a code\xe2\x80\xa6"));
    m_steps->setCurrentIndex(0);
    m_rpc.Call(TAG_TICKET, "companionpair");
}

void CompanionPairDialog::ShowExpired()
{
    m_timer->stop();
    m_qr->setPixmap(QPixmap());
    m_qr->setText(tr("This code has expired."));
    m_ticket->clear();
    m_wait->clear();
    m_again->setVisible(true);
    m_steps->setCurrentIndex(0);
}

void CompanionPairDialog::Poll()
{
    if (m_token.isEmpty() || m_answered) return;
    if (QDateTime::currentSecsSinceEpoch() > m_expires) {
        ShowExpired();
        return;
    }
    const qint64 left = m_expires - QDateTime::currentSecsSinceEpoch();
    m_wait->setText(tr("Waiting for the phone\xe2\x80\xa6 the code works for %1 more minutes.").arg((left + 59) / 60));
    m_rpc.Call(TAG_PENDING, "companionpending");
}

void CompanionPairDialog::UpdateAcceptable()
{
    bool tx_ok = false, day_ok = false;
    const CAmount per_tx = AmountOf(m_per_tx, tx_ok);
    const CAmount per_day = AmountOf(m_per_day, day_ok);
    const QString problem = LimitsProblem(tx_ok, per_tx, day_ok, per_day);
    m_error->setText(problem);
    m_accept->setEnabled(problem.isEmpty());
}

void CompanionPairDialog::Accept()
{
    bool tx_ok = false, day_ok = false;
    const CAmount per_tx = AmountOf(m_per_tx, tx_ok);
    const CAmount per_day = AmountOf(m_per_day, day_ok);
    if (!LimitsProblem(tx_ok, per_tx, day_ok, per_day).isEmpty()) return;
    UniValue params(UniValue::VARR);
    params.push_back(m_token.toStdString());
    params.push_back(ValueFromAmount(per_tx));
    params.push_back(ValueFromAmount(per_day));
    m_accept->setEnabled(false);
    m_reject->setEnabled(false);
    m_rpc.Call(TAG_ACCEPT, "companionaccept", params);
}

void CompanionPairDialog::Reject()
{
    UniValue params(UniValue::VARR);
    params.push_back(m_token.toStdString());
    m_rpc.Call(TAG_REJECT, "companionreject", params);
}

void CompanionPairDialog::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_TICKET) {
        const QString ticket = QString::fromStdString(find_value(value, "ticket").get_str());
        m_token = QString::fromStdString(find_value(value, "token").get_str());
        m_expires = find_value(value, "expires").get_int64();
        const QPixmap qr = MakeQR(ticket);
        if (qr.isNull()) {
            m_qr->setText(tr("This build cannot draw QR codes: copy the text below into the app instead."));
        } else {
            m_qr->setPixmap(qr);
        }
        m_ticket->setPlainText(ticket);
        m_timer->start();
        Poll();
        return;
    }
    if (tag == TAG_PENDING) {
        if (m_answered) return;
        for (const UniValue& p : value.getValues()) {
            if (QString::fromStdString(find_value(p, "token").get_str()) != m_token) continue;
            const std::string state = find_value(p, "state").get_str();
            if (state == "expired") {
                ShowExpired();
                return;
            }
            if (!find_value(p, "answered").isTrue()) return;
            m_answered = true;
            m_timer->stop();
            m_who->setText(tr("A phone called \xe2\x80\x9c%1\xe2\x80\x9d wants to pair with this node.")
                               .arg(QString::fromStdString(find_value(p, "name").get_str())));
            m_code->setText(Spaced(QString::fromStdString(find_value(p, "code").get_str())));
            m_steps->setCurrentIndex(1);
            UpdateAcceptable();
            return;
        }
        return;
    }
    if (tag == TAG_ACCEPT) {
        m_done->setText(tr("Paired. The phone can now spend from the allowance wallet within the limits you set. "
                           "Its list is on the Server page, where you can change its limits, unlock it after "
                           "too many wrong PINs, or unpair it."));
        m_steps->setCurrentIndex(2);
        return;
    }
    if (tag == TAG_REJECT) {
        reject();
    }
}

void CompanionPairDialog::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_TICKET) {
        m_qr->setPixmap(QPixmap());
        m_qr->setText(message);
        m_wait->clear();
        return;
    }
    if (tag == TAG_ACCEPT || tag == TAG_REJECT) {
        m_error->setText(message);
        m_accept->setEnabled(true);
        m_reject->setEnabled(true);
    }
}

CompanionLimitsDialog::CompanionLimitsDialog(const QString& phone, CAmount per_tx, CAmount per_day, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Limits for %1").arg(phone));
    QVBoxLayout* outer = new QVBoxLayout(this);
    QLabel* text = new QLabel(tr("What this phone may spend from the allowance wallet, fees included."), this);
    text->setWordWrap(true);
    outer->addWidget(text);
    QFormLayout* form = new QFormLayout();
    m_per_tx = new BitcoinAmountField(this);
    m_per_tx->setValue(per_tx);
    m_per_day = new BitcoinAmountField(this);
    m_per_day->setValue(per_day);
    form->addRow(tr("Most in one payment"), m_per_tx);
    form->addRow(tr("Most in any 24 hours"), m_per_day);
    outer->addLayout(form);
    m_error = new QLabel(this);
    m_error->setWordWrap(true);
    outer->addWidget(m_error);
    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_ok = buttons->button(QDialogButtonBox::Ok);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    outer->addWidget(buttons);
    connect(m_per_tx, &BitcoinAmountField::valueChanged, this, &CompanionLimitsDialog::Check);
    connect(m_per_day, &BitcoinAmountField::valueChanged, this, &CompanionLimitsDialog::Check);
    Check();
}

void CompanionLimitsDialog::Check()
{
    bool tx_ok = false, day_ok = false;
    const CAmount per_tx = AmountOf(m_per_tx, tx_ok);
    const CAmount per_day = AmountOf(m_per_day, day_ok);
    const QString problem = LimitsProblem(tx_ok, per_tx, day_ok, per_day);
    m_error->setText(problem);
    m_ok->setEnabled(problem.isEmpty());
}

CAmount CompanionLimitsDialog::PerTx() const
{
    return m_per_tx->value();
}

CAmount CompanionLimitsDialog::PerDay() const
{
    return m_per_day->value();
}

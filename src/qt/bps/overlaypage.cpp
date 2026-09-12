// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/overlaypage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>

#include <qt/clientmodel.h>

#include <univalue.h>

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const char* TAG_OVERLAY = "ov:info";
const int REFRESH_MS = 5000;

void FillKeys(QListWidget* list, const UniValue& array, const QString& empty_text)
{
    list->clear();
    if (!array.isArray() || array.size() == 0) {
        QListWidgetItem* item = new QListWidgetItem(empty_text);
        item->setFlags(Qt::NoItemFlags);
        list->addItem(item);
        return;
    }
    for (size_t i = 0; i < array.size(); ++i) {
        if (!array[i].isStr()) continue;
        const QString key = QString::fromStdString(array[i].get_str());
        QListWidgetItem* item = new QListWidgetItem(BpsUtil::ShortKey(key));
        item->setFont(BpsUtil::FixedPitchFont());
        item->setToolTip(key);
        list->addItem(item);
    }
}
} // namespace

OverlayPage::OverlayPage(BpsRpc& rpc, QWidget* parent) : QWidget(parent), m_rpc(rpc)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(6);

    QLabel* title = new QLabel(tr("Overlay"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("An encrypted layer of BPS's own, carrying traffic through other peers so that "
           "the far end never learns where you are."),
        this);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);

    m_off_note = new QLabel(this);
    m_off_note->setWordWrap(true);
    m_off_note->setVisible(false);
    outer->addWidget(m_off_note);
    outer->addSpacing(8);

    QFormLayout* form = new QFormLayout();
    m_state = new QLabel(tr("asking\xe2\x80\xa6"), this);
    m_listening = new QLabel(tr("\xe2\x80\x94"), this);
    m_paths = new QLabel(tr("\xe2\x80\x94"), this);
    m_introductions = new QLabel(tr("\xe2\x80\x94"), this);
    m_candidates = new QLabel(tr("\xe2\x80\x94"), this);
    m_epoch = new QLabel(tr("\xe2\x80\x94"), this);
    form->addRow(tr("Running"), m_state);
    form->addRow(tr("Listening on"), m_listening);
    form->addRow(tr("Routes open"), m_paths);
    form->addRow(tr("Services meeting here"), m_introductions);
    form->addRow(tr("Relays available"), m_candidates);
    form->addRow(tr("Today's round"), m_epoch);
    outer->addLayout(form);
    outer->addSpacing(8);

    QHBoxLayout* lists = new QHBoxLayout();

    QGroupBox* guards_box = new QGroupBox(tr("Your way in"), this);
    QVBoxLayout* guards_layout = new QVBoxLayout(guards_box);
    QLabel* guards_note = new QLabel(
        tr("The peers your traffic always enters through. They are kept rather than "
           "swapped: picking a new one each time would eventually hand a watcher a turn."),
        guards_box);
    guards_note->setWordWrap(true);
    guards_note->setEnabled(false);
    m_guards = new QListWidget(guards_box);
    guards_layout->addWidget(guards_note);
    guards_layout->addWidget(m_guards);
    lists->addWidget(guards_box);

    QGroupBox* rv_box = new QGroupBox(tr("Where people can meet you"), this);
    QVBoxLayout* rv_layout = new QVBoxLayout(rv_box);
    QLabel* rv_note = new QLabel(
        tr("Worked out from the roster, not looked up. Anyone trying to reach you does the "
           "same sum and gets the same answer, so there is nobody to ask and nobody who "
           "could answer differently. They change each day."),
        rv_box);
    rv_note->setWordWrap(true);
    rv_note->setEnabled(false);
    m_rendezvous = new QListWidget(rv_box);
    rv_layout->addWidget(rv_note);
    rv_layout->addWidget(m_rendezvous);
    lists->addWidget(rv_box);

    outer->addLayout(lists, 1);

    QLabel* caveat = new QLabel(
        tr("Not yet reviewed by anyone who did not write it, and it hides where you are "
           "rather than when you speak: someone watching both ends can still line up the "
           "timing. Treat it as unfinished."),
        this);
    caveat->setWordWrap(true);
    caveat->setEnabled(false);
    outer->addWidget(caveat);

    connect(&m_rpc, &BpsRpc::result, this, &OverlayPage::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &OverlayPage::onRpcFailed);

    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &OverlayPage::Refresh);
}

void OverlayPage::setClientModel(ClientModel* model)
{
    if (!model) {
        m_timer->stop();
        return;
    }
    m_timer->start();
    Refresh();
}

void OverlayPage::Refresh()
{
    m_rpc.Call(TAG_OVERLAY, "getoverlayinfo");
}

void OverlayPage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag != TAG_OVERLAY) return;

    const UniValue& enabled = find_value(value, "enabled");
    const bool on = enabled.isBool() && enabled.get_bool();
    m_state->setText(on ? tr("yes") : tr("no"));

    if (!on) {
        m_off_note->setVisible(true);
        m_off_note->setText(tr("The overlay is switched off. This client turns it on by itself, so "
                               "something has turned it back off, with -overlay=0 on the "
                               "command line or in the configuration file."));
        m_listening->setText(tr("\xe2\x80\x94"));
        m_paths->setText(tr("\xe2\x80\x94"));
        m_introductions->setText(tr("\xe2\x80\x94"));
        m_candidates->setText(tr("\xe2\x80\x94"));
        m_epoch->setText(tr("\xe2\x80\x94"));
        FillKeys(m_guards, UniValue(UniValue::VARR), tr("nothing while the overlay is off"));
        FillKeys(m_rendezvous, UniValue(UniValue::VARR), tr("nothing while the overlay is off"));
        return;
    }

    m_off_note->setVisible(false);

    const UniValue& listening = find_value(value, "listening");
    m_listening->setText(listening.isStr() ? QString::fromStdString(listening.get_str()) : tr("\xe2\x80\x94"));

    const UniValue& paths = find_value(value, "paths");
    m_paths->setText(paths.isNum() ? QString::number(paths.get_int()) : tr("\xe2\x80\x94"));

    const UniValue& introductions = find_value(value, "introductions");
    m_introductions->setText(introductions.isNum() ? QString::number(introductions.get_int()) : tr("\xe2\x80\x94"));

    const UniValue& candidates = find_value(value, "relay_candidates");
    // Zero is a real state on a young network and while the relay list waits
    // for its refresh, so it is worded rather than printed as a bare 0.
    m_candidates->setText(candidates.isNum() && candidates.get_int() > 0
                              ? QString::number(candidates.get_int())
                              : tr("none yet"));

    const UniValue& epoch = find_value(value, "epoch");
    m_epoch->setText(epoch.isNum() ? QString::number(epoch.get_int64()) : tr("\xe2\x80\x94"));

    FillKeys(m_guards, find_value(value, "guards"), tr("none chosen yet"));
    FillKeys(m_rendezvous, find_value(value, "rendezvous"),
             tr("none \xe2\x80\x94 the roster has no relays to derive them from"));
}

void OverlayPage::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag != TAG_OVERLAY) return;
    m_state->setText(message);
}

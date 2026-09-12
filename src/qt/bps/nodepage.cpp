// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/nodepage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/rpcconsole.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QDateTime>
#include <QFont>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const char* TAG_SUBSIDY = "node:subsidy";
const char* TAG_ROSTER = "node:roster";

//! Blocks a day at the chain's 180-second spacing.
const int BLOCKS_PER_DAY = 24 * 60 * 60 / BpsUtil::SECONDS_PER_BLOCK;

//! The figures move at block pace, so once a minute is plenty.
const int REFRESH_MS = 60000;

QLabel* MakeField(QGridLayout* grid, int row, int column, const QString& caption)
{
    QLabel* head = new QLabel(caption);
    QFont head_font = head->font();
    head_font.setPointSizeF(head_font.pointSizeF() * 0.85);
    head->setFont(head_font);
    head->setEnabled(false);

    QLabel* value = new QLabel(QString::fromUtf8("\xe2\x80\x94"));
    QFont value_font = value->font();
    value_font.setBold(true);
    value->setFont(value_font);

    grid->addWidget(head, row, column * 2);
    grid->addWidget(value, row, column * 2 + 1);
    return value;
}
} // namespace

NodePage::NodePage(BpsRpc& rpc, interfaces::Node& node, const PlatformStyle* platform_style,
                   QWidget* parent)
    : QWidget(parent), m_rpc(rpc)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(12, 12, 12, 8);
    outer->setSpacing(8);

    QGroupBox* economics = new QGroupBox(tr("What the network pays for carrying traffic"), this);
    QVBoxLayout* economics_layout = new QVBoxLayout(economics);

    QGridLayout* grid = new QGridLayout();
    grid->setHorizontalSpacing(12);
    m_reward = MakeField(grid, 0, 0, tr("Reward per block"));
    m_per_day = MakeField(grid, 0, 1, tr("Issued per day"));
    m_listed = MakeField(grid, 1, 0, tr("Peers listed"));
    m_share = MakeField(grid, 1, 1, tr("Ceiling per peer, per day"));
    grid->setColumnStretch(5, 1);
    economics_layout->addLayout(grid);

    QLabel* note = new QLabel(
        tr("A relay's income is its share of block rewards, and it shares that with the "
           "peers listed through it \xe2\x80\x94 so attracting a share of the network's users "
           "costs a share of the stake. The figure on the right is all of the issuance "
           "divided by everyone listed: the most anyone could be paid, not what anyone is "
           "paid. No payments are implemented yet."),
        economics);
    note->setWordWrap(true);
    note->setEnabled(false);
    economics_layout->addWidget(note);

    outer->addWidget(economics);

    // Below it, the wallet client's own console, peer table and traffic graph.
    m_console = new RPCConsole(node, platform_style, nullptr);
    outer->addWidget(m_console, 1);

    connect(&m_rpc, &BpsRpc::result, this, &NodePage::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &NodePage::onRpcFailed);

    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &NodePage::Refresh);
}

void NodePage::setClientModel(ClientModel* model, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    if (m_console) {
        if (model && tip_info) {
            m_console->setClientModel(model, tip_info->block_height, tip_info->block_time,
                                      tip_info->verification_progress);
        } else {
            m_console->setClientModel(model);
        }
    }

    m_client_model = model;
    if (!model) {
        m_timer->stop();
        return;
    }

    // The figures follow the chain, so recompute when it moves rather than
    // only on the timer.
    connect(model, &ClientModel::numBlocksChanged, this,
            [this](int, const QDateTime&, double, bool header, SynchronizationState) {
                if (!header) Refresh();
            });

    // Amounts follow whatever unit the operator picked, like everywhere else.
    if (model->getOptionsModel()) {
        m_display_unit = model->getOptionsModel()->getDisplayUnit();
        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this,
                [this](int unit) {
                    m_display_unit = unit;
                    UpdateShare();
                });
    }

    m_timer->start();
    Refresh();
}

void NodePage::Refresh()
{
    m_rpc.Call(TAG_ROSTER, "getrosterinfo");

    // Not getmininginfo, which would be the obvious source: this fork made it
    // ask the wallet for a stake weight through GetWalletForJSONRPCRequest,
    // which throws when no wallet is open and when two are. A node-level figure
    // should not depend on that, so the subsidy comes from getblockstats, which
    // is chain-only. Asking for the one field keeps it cheap.
    if (!m_client_model) return;
    const int height = m_client_model->getNumBlocks();
    if (height <= 0) return; // genesis carries no undo data to read

    UniValue params(UniValue::VARR);
    params.push_back(height);
    UniValue fields(UniValue::VARR);
    fields.push_back("subsidy");
    params.push_back(fields);
    m_rpc.Call(TAG_SUBSIDY, "getblockstats", params);
}

void NodePage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_SUBSIDY) {
        const UniValue& reward = find_value(value, "subsidy");
        m_subsidy = reward.isNum() ? reward.get_int64() : -1;
        UpdateShare();
        return;
    }

    if (tag == TAG_ROSTER) {
        const UniValue& live = find_value(value, "live_peers");
        m_peers = live.isNum() ? live.get_int() : -1;
        UpdateShare();
        return;
    }
}

void NodePage::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_SUBSIDY) m_subsidy = -1;
    if (tag == TAG_ROSTER) m_peers = -1;
    if (tag == TAG_SUBSIDY || tag == TAG_ROSTER) UpdateShare();
}

void NodePage::UpdateShare()
{
    const QString unknown = QString::fromUtf8("\xe2\x80\x94");

    if (m_subsidy < 0) {
        m_reward->setText(unknown);
        m_per_day->setText(unknown);
    } else {
        m_reward->setText(BitcoinUnits::formatWithUnit(m_display_unit, m_subsidy));
        m_per_day->setText(BitcoinUnits::formatWithUnit(m_display_unit,
                                                        m_subsidy * (qint64)BLOCKS_PER_DAY));
    }

    if (m_peers < 0) {
        m_listed->setText(unknown);
    } else {
        m_listed->setText(QString::number(m_peers));
    }

    // Dividing by nobody is not a large number, it is no answer at all.
    if (m_subsidy < 0 || m_peers <= 0) {
        m_share->setText(m_peers == 0 ? tr("nobody is listed") : unknown);
        return;
    }
    m_share->setText(BitcoinUnits::formatWithUnit(
        m_display_unit, (m_subsidy * (qint64)BLOCKS_PER_DAY) / (qint64)m_peers));
}

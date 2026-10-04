// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/bps/settingspage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsdialog.h>
#include <qt/optionsmodel.h>

#include <index/rosterindex.h>
#include <overlay/socket.h>
#include <roster/listing.h>
#include <roster/payout.h>
#include <roster/peers.h>
#include <util/system.h>

#include <QCheckBox>
#include <QComboBox>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {
//! QSettings keys. Prefixed, because this client shares an organisation name
//! with the wallet client even though it has its own application name.
const char* KEY_ROSTERINDEX = "bps/rosterindex";
const char* KEY_ROSTERCONNECT = "bps/rosterconnect";
const char* KEY_OVERLAY = "bps/overlay";
const char* KEY_OVERLAYPORT = "bps/overlayport";
const char* KEY_ACCEPTLISTINGS = "bps/acceptlistings";
const char* KEY_MAXLISTEDUSERS = "bps/maxlistedusers";
const char* KEY_LISTINGWALLET = "bps/listingwallet";
const char* KEY_RELAYSHARE = "bps/relayshare";
} // namespace

void SettingsPage::ApplyStoredSettings()
{
    QSettings settings;

    // Defaults differ from the node's on purpose: discovery is what this client
    // is for. See BpsApplication::parameterSetup.
    if (!settings.contains(KEY_ROSTERINDEX)) settings.setValue(KEY_ROSTERINDEX, true);
    if (!settings.contains(KEY_ROSTERCONNECT)) {
        settings.setValue(KEY_ROSTERCONNECT, roster::DEFAULT_ROSTERCONNECT);
    }
    if (!settings.contains(KEY_OVERLAY)) settings.setValue(KEY_OVERLAY, true);
    if (!settings.contains(KEY_OVERLAYPORT)) {
        settings.setValue(KEY_OVERLAYPORT, (int)overlay::DEFAULT_OVERLAY_PORT);
    }

    gArgs.SoftSetBoolArg("-rosterindex", settings.value(KEY_ROSTERINDEX).toBool());
    gArgs.SoftSetBoolArg("-rosterconnect", settings.value(KEY_ROSTERCONNECT).toBool());
    gArgs.SoftSetBoolArg("-overlay", settings.value(KEY_OVERLAY).toBool());
    gArgs.SoftSetArg("-overlayport",
                     settings.value(KEY_OVERLAYPORT).toString().toStdString());

    // Paying for other peers' listings spends coins, so it stays off unless the
    // operator turns it on here; the node's own defaults apply until then.
    if (settings.contains(KEY_ACCEPTLISTINGS)) {
        gArgs.SoftSetBoolArg("-acceptlistings", settings.value(KEY_ACCEPTLISTINGS).toBool());
    }
    if (settings.contains(KEY_MAXLISTEDUSERS)) {
        gArgs.SoftSetArg("-maxlistedusers", settings.value(KEY_MAXLISTEDUSERS).toString().toStdString());
    }
    const QString listing_wallet = settings.value(KEY_LISTINGWALLET).toString();
    if (!listing_wallet.isEmpty()) gArgs.SoftSetArg("-listingwallet", listing_wallet.toStdString());
    if (settings.contains(KEY_RELAYSHARE)) {
        gArgs.SoftSetArg("-relayshare", settings.value(KEY_RELAYSHARE).toString().toStdString());
    }
}

SettingsPage::SettingsPage(const PlatformStyle* platform_style, QWidget* parent)
    : QWidget(parent), m_platform_style(platform_style)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(8);

    QLabel* title = new QLabel(tr("Settings"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("What this client does that the wallet client does not. Everything else "
           "\xe2\x80\x94 proxy, ports, pruning, language \xe2\x80\x94 is the same question in both, "
           "and is asked in one place."),
        this);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);
    outer->addSpacing(8);

    // --- discovery ---------------------------------------------------------
    QGroupBox* discovery = new QGroupBox(tr("Discovery"), this);
    QVBoxLayout* discovery_layout = new QVBoxLayout(discovery);

    m_rosterindex = new QCheckBox(tr("Keep an index of the roster"), discovery);
    m_rosterindex->setToolTip(tr("Without it this node can publish but cannot see who else is listed."));
    discovery_layout->addWidget(m_rosterindex);

    m_rosterconnect = new QCheckBox(tr("Try to connect to peers found in the roster"), discovery);
    m_rosterconnect->setToolTip(tr("Hands roster addresses to the address manager, alongside the "
                                   "usual seeds and gossip. Turning it off leaves the roster a "
                                   "list this node reads but never acts on."));
    discovery_layout->addWidget(m_rosterconnect);
    outer->addWidget(discovery);

    // --- overlay -----------------------------------------------------------
    QGroupBox* overlay_box = new QGroupBox(tr("Overlay"), this);
    QVBoxLayout* overlay_layout = new QVBoxLayout(overlay_box);

    m_overlay = new QCheckBox(tr("Run the overlay"), overlay_box);
    m_overlay->setToolTip(tr("On by default in this client, off in the node and in the wallet "
                             "client. Its handshake has not been reviewed by anyone who did not "
                             "write it."));
    overlay_layout->addWidget(m_overlay);

    QFormLayout* overlay_form = new QFormLayout();
    m_overlayport = new QSpinBox(overlay_box);
    m_overlayport->setRange(1, 65535);
    m_overlayport->setToolTip(tr("The overlay speaks UDP on its own port. The peer-to-peer "
                                 "network is separate and stays on TCP."));
    overlay_form->addRow(tr("Listen on port"), m_overlayport);
    overlay_layout->addLayout(overlay_form);
    outer->addWidget(overlay_box);

    // --- relay -------------------------------------------------------------
    // What this node does for peers that use it: pay for their listings, and
    // share its staking rewards with them (design note 001 section 8).
    QGroupBox* relay_box = new QGroupBox(tr("Relay"), this);
    QVBoxLayout* relay_layout = new QVBoxLayout(relay_box);

    m_acceptlistings = new QCheckBox(tr("Pay to list peers that ask through the overlay"), relay_box);
    m_acceptlistings->setToolTip(tr("A peer with no coins can ask this node to publish its monthly "
                                    "listing. This node pays the fee and adds the peer to those it "
                                    "shares rewards with. Off by default, because it spends this "
                                    "node's coins."));
    relay_layout->addWidget(m_acceptlistings);

    QFormLayout* relay_form = new QFormLayout();
    m_maxlistedusers = new QSpinBox(relay_box);
    m_maxlistedusers->setRange(1, 100000);
    m_maxlistedusers->setToolTip(tr("Peers past this number are turned away. Peers already listed "
                                    "here can still renew."));
    relay_form->addRow(tr("Most peers to keep listed"), m_maxlistedusers);

    m_listingwallet = new QLineEdit(relay_box);
    m_listingwallet->setPlaceholderText(tr("the only wallet open"));
    m_listingwallet->setToolTip(tr("Which wallet pays. With several open and none named here, "
                                   "requests are declined rather than paid from a guess. A small "
                                   "unencrypted wallet keeps a staking wallet locked."));
    relay_form->addRow(tr("Pay from wallet"), m_listingwallet);

    m_relayshare = new QSpinBox(relay_box);
    m_relayshare->setRange(0, 100);
    m_relayshare->setSuffix(tr(" %"));
    m_relayshare->setToolTip(tr("Part of every block this node stakes from its own coins, split "
                                "equally among the peers it lists. 0 shares nothing."));
    relay_form->addRow(tr("Share of each staked block"), m_relayshare);
    relay_layout->addLayout(relay_form);
    outer->addWidget(relay_box);

    // --- display -----------------------------------------------------------
    QGroupBox* display = new QGroupBox(tr("Display"), this);
    QFormLayout* display_form = new QFormLayout(display);
    m_unit = new QComboBox(display);
    display_form->addRow(tr("Show amounts in"), m_unit);
    outer->addWidget(display);

    m_restart_note = new QLabel(this);
    m_restart_note->setWordWrap(true);
    m_restart_note->setVisible(false);
    outer->addWidget(m_restart_note);

    QHBoxLayout* buttons = new QHBoxLayout();
    m_core_options = new QPushButton(tr("Network, proxy and other core settings\xe2\x80\xa6"), this);
    buttons->addWidget(m_core_options);
    buttons->addStretch(1);
    outer->addLayout(buttons);

    outer->addStretch(1);

    connect(m_rosterindex, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_rosterconnect, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_overlay, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_overlayport, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_acceptlistings, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_maxlistedusers, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_listingwallet, &QLineEdit::editingFinished, this, &SettingsPage::onChanged);
    connect(m_relayshare, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_core_options, &QPushButton::clicked, this, &SettingsPage::onOpenCoreOptions);

    Load();
}

void SettingsPage::Load()
{
    m_loading = true;
    QSettings settings;
    m_rosterindex->setChecked(settings.value(KEY_ROSTERINDEX, true).toBool());
    m_rosterconnect->setChecked(settings.value(KEY_ROSTERCONNECT, roster::DEFAULT_ROSTERCONNECT).toBool());
    m_overlay->setChecked(settings.value(KEY_OVERLAY, true).toBool());
    m_overlayport->setValue(settings.value(KEY_OVERLAYPORT, (int)overlay::DEFAULT_OVERLAY_PORT).toInt());
    // What the node is running with, so a value from the command line or the
    // config file shows here rather than being contradicted by the page.
    m_acceptlistings->setChecked(gArgs.GetBoolArg("-acceptlistings", roster::DEFAULT_ACCEPT_LISTINGS));
    m_maxlistedusers->setValue((int)gArgs.GetArg("-maxlistedusers", roster::DEFAULT_MAX_LISTED_USERS));
    m_listingwallet->setText(QString::fromStdString(gArgs.GetArg("-listingwallet", "")));
    m_relayshare->setValue((int)gArgs.GetArg("-relayshare", roster::DEFAULT_RELAY_SHARE));
    m_loading = false;
}

void SettingsPage::setClientModel(ClientModel* model)
{
    m_client_model = model;
    m_options_model = model ? model->getOptionsModel() : nullptr;
    if (!m_options_model) return;

    m_loading = true;
    m_unit->clear();
    // Whatever the shared list offers, so the two clients and the core options
    // dialog never disagree about which units exist.
    const QList<BitcoinUnits::Unit> units = BitcoinUnits::availableUnits();
    for (int i = 0; i < units.size(); ++i) {
        m_unit->addItem(BitcoinUnits::longName(units.at(i)), units.at(i));
    }
    const int current = m_unit->findData(m_options_model->getDisplayUnit());
    if (current >= 0) m_unit->setCurrentIndex(current);
    m_loading = false;

    connect(m_unit, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &SettingsPage::onDisplayUnitChanged);
}

void SettingsPage::onDisplayUnitChanged(int index)
{
    if (m_loading || !m_options_model || index < 0) return;
    // The display unit is the one setting here that takes effect at once,
    // because it is the GUI's own rather than the node's.
    m_options_model->setDisplayUnit(m_unit->itemData(index));
}

void SettingsPage::onChanged()
{
    if (m_loading) return;

    QSettings settings;
    settings.setValue(KEY_ROSTERINDEX, m_rosterindex->isChecked());
    settings.setValue(KEY_ROSTERCONNECT, m_rosterconnect->isChecked());
    settings.setValue(KEY_OVERLAY, m_overlay->isChecked());
    settings.setValue(KEY_OVERLAYPORT, m_overlayport->value());
    settings.setValue(KEY_ACCEPTLISTINGS, m_acceptlistings->isChecked());
    settings.setValue(KEY_MAXLISTEDUSERS, m_maxlistedusers->value());
    settings.setValue(KEY_LISTINGWALLET, m_listingwallet->text().trimmed());
    settings.setValue(KEY_RELAYSHARE, m_relayshare->value());

    m_restart_note->setVisible(true);
    m_restart_note->setText(tr("Saved. These are read when the node starts, so restart the "
                               "client for the change to take effect."));
}

void SettingsPage::onOpenCoreOptions()
{
    if (!m_options_model) {
        Q_EMIT message(tr("Settings"),
                       tr("The node is still starting; core settings are not available yet."),
                       0);
        return;
    }
#ifdef ENABLE_WALLET
    const bool wallet_enabled = true;
#else
    const bool wallet_enabled = false;
#endif
    OptionsDialog dialog(this, wallet_enabled);
    dialog.setModel(m_options_model);
    dialog.exec();
}

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

#include <chainparams.h>
#include <index/rosterindex.h>
#include <overlay/socket.h>
#include <roster/peers.h>
#include <util/system.h>

#include <QCheckBox>
#include <QComboBox>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {
//! QSettings keys. Prefixed, because this client shares an organisation name
//! with the wallet client even though it has its own application name.
const char* KEY_ROSTERINDEX = "bps/rosterindex";
const char* KEY_NAMEINDEX = "bps/nameindex";
const char* KEY_ROSTERCONNECT = "bps/rosterconnect";
const char* KEY_OVERLAY = "bps/overlay";
const char* KEY_OVERLAYPORT = "bps/overlayport";
} // namespace

void SettingsPage::ApplyStoredSettings()
{
    QSettings settings;

    // Defaults differ from the node's on purpose: discovery is what this client
    // is for. See BpsApplication::parameterSetup.
    if (!settings.contains(KEY_ROSTERINDEX)) settings.setValue(KEY_ROSTERINDEX, true);
    if (!settings.contains(KEY_NAMEINDEX)) settings.setValue(KEY_NAMEINDEX, true);
    if (!settings.contains(KEY_ROSTERCONNECT)) {
        settings.setValue(KEY_ROSTERCONNECT, roster::DEFAULT_ROSTERCONNECT);
    }
    if (!settings.contains(KEY_OVERLAY)) settings.setValue(KEY_OVERLAY, true);
    // The first builds stored a fixed 9346 here on first run. That is neither
    // one above this chain's peer-to-peer port nor different per network, so
    // it is dropped and the node's own default applies.
    if (settings.value(KEY_OVERLAYPORT).toInt() == 9346) settings.remove(KEY_OVERLAYPORT);

    gArgs.SoftSetBoolArg("-rosterindex", settings.value(KEY_ROSTERINDEX).toBool());
    gArgs.SoftSetBoolArg("-nameindex", settings.value(KEY_NAMEINDEX).toBool());
    gArgs.SoftSetBoolArg("-rosterconnect", settings.value(KEY_ROSTERCONNECT).toBool());
    gArgs.SoftSetBoolArg("-overlay", settings.value(KEY_OVERLAY).toBool());
    if (settings.contains(KEY_OVERLAYPORT)) {
        gArgs.SoftSetArg("-overlayport", settings.value(KEY_OVERLAYPORT).toString().toStdString());
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
    m_nameindex = new QCheckBox(tr("Index names"), discovery);
    m_nameindex->setToolTip(tr("Needed to look names up, send mail to them and register your own."));
    discovery_layout->addWidget(m_nameindex);

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
    connect(m_nameindex, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_rosterconnect, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_overlay, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_overlayport, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_core_options, &QPushButton::clicked, this, &SettingsPage::onOpenCoreOptions);

    Load();
}

void SettingsPage::Load()
{
    m_loading = true;
    QSettings settings;
    m_rosterindex->setChecked(settings.value(KEY_ROSTERINDEX, true).toBool());
    m_nameindex->setChecked(settings.value(KEY_NAMEINDEX, true).toBool());
    m_rosterconnect->setChecked(settings.value(KEY_ROSTERCONNECT, roster::DEFAULT_ROSTERCONNECT).toBool());
    m_overlay->setChecked(settings.value(KEY_OVERLAY, true).toBool());
    m_overlayport->setValue((int)gArgs.GetArg("-overlayport", overlay::OverlayPortFor((uint16_t)gArgs.GetArg("-port", Params().GetDefaultPort()))));
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
    settings.setValue(KEY_NAMEINDEX, m_nameindex->isChecked());
    settings.setValue(KEY_ROSTERCONNECT, m_rosterconnect->isChecked());
    settings.setValue(KEY_OVERLAY, m_overlay->isChecked());
    settings.setValue(KEY_OVERLAYPORT, m_overlayport->value());

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

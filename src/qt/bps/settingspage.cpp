// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/bps/settingspage.h>

#include <qt/bps/bpsutil.h>
#include <qt/bps/radiobridge.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsdialog.h>
#include <qt/optionsmodel.h>

#include <chainparams.h>
#include <clientversion.h>
#include <index/rosterindex.h>
#include <overlay/gatewayclient.h>
#include <overlay/meeting.h>
#include <overlay/radio.h>
#include <overlay/socket.h>
#include <roster/peers.h>
#include <util/system.h>

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QLocale>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
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
const char* KEY_MEETHOPS = "bps/meethops";
const char* KEY_GATEWAYHOPS = "bps/gatewayhops";
const char* KEY_RADIO = "bps/radio";
const char* KEY_RADIOENTRY = "bps/radioentry";
const char* KEY_RADIOBRIDGE = "bps/radiobridge";
const char* KEY_PYTHON = "bps/python";
} // namespace

bool SettingsPage::StartRadioBridge()
{
    return QSettings().value(KEY_RADIOBRIDGE, true).toBool();
}

QString SettingsPage::PythonCommand()
{
    const QString stored = QSettings().value(KEY_PYTHON).toString().trimmed();
    return stored.isEmpty() ? RadioBridge::DefaultPython() : stored;
}

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
    if (settings.contains(KEY_MEETHOPS)) {
        gArgs.SoftSetArg("-meethops", settings.value(KEY_MEETHOPS).toString().toStdString());
    }
    if (settings.contains(KEY_GATEWAYHOPS)) {
        gArgs.SoftSetArg("-gatewayhops", settings.value(KEY_GATEWAYHOPS).toString().toStdString());
    }
    gArgs.SoftSetBoolArg("-radio", settings.value(KEY_RADIO, overlay::DEFAULT_RADIO).toBool());
    gArgs.SoftSetBoolArg("-radioentry", settings.value(KEY_RADIOENTRY, overlay::DEFAULT_RADIO_ENTRY).toBool());
    // Sites in an ordinary browser, through a server on this computer only
    // (overlay/siteproxy.h): part of this client, off in the node.
    gArgs.SoftSetBoolArg("-siteproxy", true);
}

SettingsPage::SettingsPage(const PlatformStyle* platform_style, QWidget* parent)
    : QWidget(parent), m_platform_style(platform_style)
{
    // In a scroll area, as the Server page is: in a window shorter than the
    // page the rows would otherwise be squeezed until they overlap.
    QVBoxLayout* page = new QVBoxLayout(this);
    page->setContentsMargins(0, 0, 0, 0);
    QScrollArea* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    page->addWidget(scroll);
    QWidget* content = new QWidget(scroll);
    scroll->setWidget(content);
    QVBoxLayout* outer = new QVBoxLayout(content);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(8);

    QLabel* title = new QLabel(tr("Settings"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("What this client does that the wallet client does not, and the language. Everything else "
           "\xe2\x80\x94 proxy, ports, pruning \xe2\x80\x94 is the same question in both, and is asked "
           "in one place."),
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

    // Only the first connection is direct: to an entry relay, which sees this
    // computer's address and, unless it relays itself, a key made for that
    // connection. Everything after it goes through relays, as many as set here.
    m_meethops = new QSpinBox(overlay_box);
    m_meethops->setRange(1, overlay::MAX_MEET_HOPS);
    m_meethops->setToolTip(tr("Others meet you at relays worked out from the roster, and your node keeps a path "
                              "open to each of them through this many relays. The meeting point sees only the "
                              "last of them, never your address. More hides you better and is slower."));
    overlay_form->addRow(tr("Relays before your meeting points"), m_meethops);
    m_gatewayhops = new QSpinBox(overlay_box);
    m_gatewayhops->setRange(1, overlay::MAX_MEET_HOPS);
    m_gatewayhops->setToolTip(tr("When this computer uses the network's internet, each connection goes through this "
                                 "many relays to a gateway's meeting point, and through the gateway's own after it: "
                                 "the gateway never learns who you are. More hides you better and is slower."));
    overlay_form->addRow(tr("Relays before a gateway's meeting point"), m_gatewayhops);
    overlay_layout->addLayout(overlay_form);

    QLabel* hops_note = new QLabel(tr("Only your first connection is direct, to an entry relay that sees your address "
                                      "and not who you are. Mail always goes through three relays."),
                                   overlay_box);
    hops_note->setWordWrap(true);
    hops_note->setEnabled(false);
    overlay_layout->addWidget(hops_note);
    outer->addWidget(overlay_box);

    // --- radio -------------------------------------------------------------
    QGroupBox* radio_box = new QGroupBox(tr("Radio"), this);
    QVBoxLayout* radio_layout = new QVBoxLayout(radio_box);
    m_radio = new QCheckBox(tr("Carry the overlay over radio too, through Reticulum"), radio_box);
    m_radio->setToolTip(tr("LoRa through an RNode, packet radio, serial links: whatever Reticulum is set up "
                           "to use. Needs the overlay."));
    radio_layout->addWidget(m_radio);
    m_radioentry = new QCheckBox(tr("Enter the overlay through radio neighbours, so mail works without the internet"),
                                 radio_box);
    m_radioentry->setToolTip(tr("When a BPS node heard on the radio is a listed relay, your mail and listing "
                                "requests go through it. A radio link is much slower than the internet."));
    radio_layout->addWidget(m_radioentry);
    m_radiobridge = new QCheckBox(tr("Start the Reticulum bridge with BPS Relay"), radio_box);
    m_radiobridge->setToolTip(tr("Runs bps-rns-bridge.py beside the node. Leave it off if you run the bridge "
                                 "yourself."));
    radio_layout->addWidget(m_radiobridge);
    QFormLayout* radio_form = new QFormLayout();
    m_python = new QLineEdit(radio_box);
    m_python->setPlaceholderText(RadioBridge::DefaultPython());
    radio_form->addRow(tr("Python command"), m_python);
    radio_layout->addLayout(radio_form);
    QLabel* radio_note = new QLabel(
        tr("Reticulum is not part of BPS and has its own licence. Install it with %1, and set up your radio "
           "in Reticulum's own configuration (~/.reticulum/config). Ham radio bands do not allow encrypted "
           "traffic, so use licence-free bands such as LoRa's.").arg("<b>pip install rns</b>"),
        radio_box);
    radio_note->setWordWrap(true);
    radio_note->setEnabled(false);
    radio_layout->addWidget(radio_note);
    outer->addWidget(radio_box);

    // --- display -----------------------------------------------------------
    QGroupBox* display = new QGroupBox(tr("Display"), this);
    QFormLayout* display_form = new QFormLayout(display);
    m_unit = new QComboBox(display);
    display_form->addRow(tr("Show amounts in"), m_unit);
    // The same list and the same setting as the wallet client's options:
    // every translation the client carries, by its own name.
    m_language = new QComboBox(display);
    m_language->addItem(tr("The computer's language"), QString());
    for (const QString& code : QDir(":translations").entryList()) {
        const QLocale locale(code);
        QString name = locale.nativeLanguageName();
        if (name.isEmpty()) name = code;
        name[0] = name[0].toUpper();
        if (code.contains('_')) name += QString(" \xe2\x80\x94 ") + locale.nativeCountryName();
        m_language->addItem(name + QString(" (%1)").arg(code), code);
    }
    {
        const int current = m_language->findData(QSettings().value("language", QString()).toString());
        m_language->setCurrentIndex(current >= 0 ? current : 0);
    }
    m_language->setToolTip(tr("Takes effect when BPS Relay starts again. Texts the node itself sends, such "
                              "as error messages from commands, stay in English."));
    display_form->addRow(tr("Language"), m_language);
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

    // Which build this is, with the commit it was made from, so two copies of
    // the program that both say 0.22 can still be told apart.
    QLabel* version = new QLabel(tr("Version %1").arg(QString::fromStdString(FormatFullVersion())), this);
    version->setTextInteractionFlags(Qt::TextSelectableByMouse);
    version->setEnabled(false);
    outer->addWidget(version);

    outer->addStretch(1);

    connect(m_rosterindex, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_nameindex, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_rosterconnect, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_overlay, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_overlayport, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_meethops, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_gatewayhops, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &SettingsPage::onChanged);
    connect(m_radio, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_radioentry, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_radiobridge, &QCheckBox::toggled, this, &SettingsPage::onChanged);
    connect(m_python, &QLineEdit::editingFinished, this, &SettingsPage::onChanged);
    connect(m_core_options, &QPushButton::clicked, this, &SettingsPage::onOpenCoreOptions);
    connect(m_language, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &SettingsPage::onLanguageChanged);

    BpsUtil::KeepWheelForPage(this);
    BpsUtil::TidyForms(this);
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
    m_meethops->setValue((int)gArgs.GetArg("-meethops", settings.value(KEY_MEETHOPS, overlay::DEFAULT_MEET_HOPS).toInt()));
    m_gatewayhops->setValue((int)gArgs.GetArg("-gatewayhops",
                                              settings.value(KEY_GATEWAYHOPS, overlay::DEFAULT_GATEWAY_HOPS).toInt()));
    // What the node runs with: the stored choice, unless the command line or
    // the configuration file said otherwise.
    m_radio->setChecked(gArgs.GetBoolArg("-radio", settings.value(KEY_RADIO, overlay::DEFAULT_RADIO).toBool()));
    m_radioentry->setChecked(gArgs.GetBoolArg("-radioentry",
                                              settings.value(KEY_RADIOENTRY, overlay::DEFAULT_RADIO_ENTRY).toBool()));
    m_radiobridge->setChecked(settings.value(KEY_RADIOBRIDGE, true).toBool());
    m_python->setText(settings.value(KEY_PYTHON).toString());
    m_radioentry->setEnabled(m_radio->isChecked());
    m_radiobridge->setEnabled(m_radio->isChecked());
    m_python->setEnabled(m_radio->isChecked());
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

void SettingsPage::onLanguageChanged(int index)
{
    if (m_loading || index < 0) return;
    const QString code = m_language->itemData(index).toString();
    // Through the options model when there is one, so the wallet client's
    // options dialog, which reads the same setting, agrees.
    if (m_options_model) {
        m_options_model->setData(m_options_model->index(OptionsModel::Language, 0), code);
    } else {
        QSettings().setValue("language", code);
    }
    m_restart_note->setVisible(true);
    m_restart_note->setText(tr("Saved. The language changes when BPS Relay starts again."));
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
    settings.setValue(KEY_MEETHOPS, m_meethops->value());
    settings.setValue(KEY_GATEWAYHOPS, m_gatewayhops->value());
    settings.setValue(KEY_RADIO, m_radio->isChecked());
    settings.setValue(KEY_RADIOENTRY, m_radioentry->isChecked());
    settings.setValue(KEY_RADIOBRIDGE, m_radiobridge->isChecked());
    settings.setValue(KEY_PYTHON, m_python->text().trimmed());
    m_radioentry->setEnabled(m_radio->isChecked());
    m_radiobridge->setEnabled(m_radio->isChecked());
    m_python->setEnabled(m_radio->isChecked());

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

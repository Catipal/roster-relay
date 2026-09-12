// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_SETTINGSPAGE_H
#define BITCOIN_QT_BPS_SETTINGSPAGE_H

#include <QWidget>

class ClientModel;
class OptionsModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QSpinBox;
QT_END_NAMESPACE

/**
 * The settings this client has that the wallet client does not.
 *
 * Only those. Proxy, ports, pruning, language and the rest are the same
 * questions in both clients, so the button at the bottom opens
 * qt/optionsdialog.cpp rather than asking them a second time here.
 *
 * What is here is the roster and the overlay: whether to keep the index,
 * whether to hand roster peers to the address manager, whether to run the
 * overlay and on which port. All four are startup arguments in the node, so
 * they are stored the way OptionsModel stores its own - in QSettings, soft-set
 * into the argument list at startup - which means a value on the command line
 * or in the config file still wins, and a change here takes effect at the next
 * start. The page says so rather than letting an operator think it took.
 */
class SettingsPage : public QWidget
{
    Q_OBJECT

public:
    explicit SettingsPage(const PlatformStyle* platform_style, QWidget* parent = nullptr);

    void setClientModel(ClientModel* model);

    /**
     * Read the stored values into the argument list, before the node starts.
     *
     * Soft, so anything the operator passed on the command line or wrote in the
     * config file takes precedence over what the page last saved.
     */
    static void ApplyStoredSettings();

Q_SIGNALS:
    void message(const QString& title, const QString& message, unsigned int style);

private Q_SLOTS:
    void onChanged();
    void onOpenCoreOptions();
    void onDisplayUnitChanged(int index);

private:
    void Load();

    const PlatformStyle* m_platform_style;
    ClientModel* m_client_model{nullptr};
    OptionsModel* m_options_model{nullptr};
    bool m_loading{false};

    QCheckBox* m_rosterindex{nullptr};
    QCheckBox* m_rosterconnect{nullptr};
    QCheckBox* m_overlay{nullptr};
    QSpinBox* m_overlayport{nullptr};
    QComboBox* m_unit{nullptr};
    QLabel* m_restart_note{nullptr};
    QPushButton* m_core_options{nullptr};
};

#endif // BITCOIN_QT_BPS_SETTINGSPAGE_H

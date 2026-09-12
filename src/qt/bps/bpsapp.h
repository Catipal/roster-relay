// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_BPSAPP_H
#define BITCOIN_QT_BPS_BPSAPP_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <interfaces/node.h>

#include <QApplication>

#include <assert.h>
#include <memory>

class BpsWindow;
class ClientModel;
class NetworkStyle;
class OptionsModel;
class PlatformStyle;
class SplashScreen;

QT_BEGIN_NAMESPACE
class QThread;
class QTimer;
class QWidget;
QT_END_NAMESPACE

/**
 * The discovery client's application object.
 *
 * The one piece that could not simply be reused. BitcoinApplication holds its
 * window as a BitcoinGUI* and drives it directly, so a different window means a
 * different application object - there is no seam to hook into that would not
 * mean editing the wallet client's files.
 *
 * What it deliberately does NOT duplicate is anything that touches the core
 * layer. Startup and shutdown still run through BitcoinCore, declared in
 * qt/bitcoin.h and linked from the same library, so a change to how the node
 * starts is inherited rather than mirrored. The same goes for OptionsModel,
 * ClientModel, SplashScreen, Intro and the platform styling. What is left here
 * is Qt plumbing - a thread, two timers and a splash - which does not change
 * when consensus, the roster or the overlay do.
 */
class BpsApplication : public QApplication
{
    Q_OBJECT

public:
    explicit BpsApplication();
    ~BpsApplication();

    void setupPlatformStyle();
    void parameterSetup();
    void createOptionsModel(bool reset_settings);
    void InitializePruneSetting(bool prune);
    void createWindow(const NetworkStyle* network_style);
    void createSplashScreen(const NetworkStyle* network_style);
    bool baseInitialize();

    void requestInitialize();
    void requestShutdown();

    int getReturnValue() const { return m_return_value; }
    WId getMainWinId() const;

    interfaces::Node& node() const { assert(m_node); return *m_node; }
    void setNode(interfaces::Node& node);

public Q_SLOTS:
    void initializeResult(bool success, interfaces::BlockAndHeaderTipInfo tip_info);
    void shutdownResult();
    void handleRunawayException(const QString& message);

Q_SIGNALS:
    void requestedInitialize();
    void requestedShutdown();
    void splashFinished();

private:
    void startThread();

    QThread* m_core_thread{nullptr};
    OptionsModel* m_options_model{nullptr};
    ClientModel* m_client_model{nullptr};
    BpsWindow* m_window{nullptr};
    QTimer* m_poll_shutdown_timer{nullptr};
    int m_return_value{0};
    const PlatformStyle* m_platform_style{nullptr};
    std::unique_ptr<QWidget> m_shutdown_window;
    SplashScreen* m_splash{nullptr};
    interfaces::Node* m_node{nullptr};
};

/** Entry point, called from qt/bps/bpsmain.cpp. */
int BpsGuiMain(int argc, char* argv[]);

#endif // BITCOIN_QT_BPS_BPSAPP_H

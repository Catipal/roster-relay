// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/bps/bpsapp.h>
#include <qt/bps/bpswindow.h>
#include <qt/bps/serverpage.h>
#include <qt/bps/settingspage.h>

// The wallet client's own startup worker, its models and its dialogs. Linked,
// not copied: this is what keeps the two clients from drifting.
#include <qt/bitcoin.h>
#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/intro.h>
#include <qt/networkstyle.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/splashscreen.h>
#include <qt/utilitydialog.h>

#ifdef ENABLE_WALLET
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#endif

#include <amount.h>
#include <chainparams.h>
#include <init.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <node/context.h>
#include <node/ui_interface.h>
#include <noui.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <validation.h>

#include <boost/signals2/connection.hpp>

#include <QDebug>
#include <QLibraryInfo>
#include <QLocale>
#include <QMessageBox>
#include <QScopedPointer>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <QTranslator>

#include <functional>
#include <memory>

#if defined(QT_STATICPLUGIN)
#include <QtPlugin>
#if defined(QT_QPA_PLATFORM_XCB)
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_WINDOWS)
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_COCOA)
Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin);
#endif
#endif

// Declared for QMetaObject::invokeMethod and queued connections, exactly as
// qt/bitcoin.cpp declares them for the wallet client.
Q_DECLARE_METATYPE(bool*)
Q_DECLARE_METATYPE(SynchronizationState)

namespace {

//! QSettings namespace, so the two clients do not fight over one another's
//! window geometry and options.
const char* BPS_APP_NAME = "BPS-Relay";

//! What this client calls itself on every screen it shares with the wallet
//! client, starting with the splash and the data directory chooser.
const char* BPS_CLIENT_NAME = "Bitcoin PoS Relay";

void RegisterMetaTypes()
{
    qRegisterMetaType<bool*>();
    qRegisterMetaType<SynchronizationState>();
#ifdef ENABLE_WALLET
    qRegisterMetaType<WalletModel*>();
#endif
    qRegisterMetaType<CAmount>("CAmount");
    qRegisterMetaType<size_t>("size_t");
    qRegisterMetaType<std::function<void()> >("std::function<void()>");
    qRegisterMetaType<QMessageBox::Icon>("QMessageBox::Icon");
    qRegisterMetaType<interfaces::BlockAndHeaderTipInfo>("interfaces::BlockAndHeaderTipInfo");
}

QString GetLangTerritory()
{
    QSettings settings;
    QString lang_territory = QLocale::system().name();
    const QString from_settings = settings.value("language", "").toString();
    if (!from_settings.isEmpty()) lang_territory = from_settings;
    return QString::fromStdString(gArgs.GetArg("-lang", lang_territory.toStdString()));
}

void InitTranslations(QTranslator& qt_base, QTranslator& qt_locale,
                      QTranslator& base, QTranslator& locale)
{
    QApplication::removeTranslator(&qt_base);
    QApplication::removeTranslator(&qt_locale);
    QApplication::removeTranslator(&base);
    QApplication::removeTranslator(&locale);

    const QString lang_territory = GetLangTerritory();
    QString lang = lang_territory;
    lang.truncate(lang_territory.lastIndexOf('_'));

    const QString qt_path = QLibraryInfo::location(QLibraryInfo::TranslationsPath);
    if (qt_base.load("qt_" + lang, qt_path)) QApplication::installTranslator(&qt_base);
    if (qt_locale.load("qt_" + lang_territory, qt_path)) QApplication::installTranslator(&qt_locale);
    // The wallet client's translations, from the same resource bundle.
    if (base.load(lang, ":/translations/")) QApplication::installTranslator(&base);
    if (locale.load(lang_territory, ":/translations/")) QApplication::installTranslator(&locale);
}

void DebugMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
    Q_UNUSED(context);
    if (type == QtDebugMsg) {
        LogPrint(BCLog::QT, "GUI: %s\n", msg.toStdString());
    } else {
        LogPrintf("GUI: %s\n", msg.toStdString());
    }
}

int qt_argc = 1;
const char* qt_argv = "bps-relay";

} // namespace

BpsApplication::BpsApplication()
    : QApplication(qt_argc, const_cast<char**>(&qt_argv))
{
    RegisterMetaTypes();
    setQuitOnLastWindowClosed(false);
}

BpsApplication::~BpsApplication()
{
    if (m_core_thread) {
        m_core_thread->quit();
        m_core_thread->wait();
    }
    delete m_window;
    m_window = nullptr;
    delete m_platform_style;
    m_platform_style = nullptr;
}

void BpsApplication::setupPlatformStyle()
{
    const std::string name = gArgs.GetArg("-uiplatform", BitcoinGUI::DEFAULT_UIPLATFORM);
    m_platform_style = PlatformStyle::instantiate(QString::fromStdString(name));
    if (!m_platform_style) m_platform_style = PlatformStyle::instantiate("other");
    assert(m_platform_style);
}

void BpsApplication::parameterSetup()
{
    gArgs.SoftSetBoolArg("-printtoconsole", false);

    // What makes this a separate client rather than a second window on the same
    // one. Discovery is the whole purpose here, so the roster index and the
    // overlay are on unless the operator turns them off; in the node and in the
    // wallet client they stay off, because there they are an extra nobody asked
    // for. The settings page owns these now - it stores them and soft-sets
    // them, so anything on the command line or in the config file still wins.
    SettingsPage::ApplyStoredSettings();
    ServerPage::ApplyStoredSettings();

    InitLogging(gArgs);
    InitParameterInteraction(gArgs);
}

void BpsApplication::createOptionsModel(bool reset_settings)
{
    m_options_model = new OptionsModel(this, reset_settings);
}

void BpsApplication::InitializePruneSetting(bool prune)
{
    m_options_model->SetPruneTargetGB(prune ? DEFAULT_PRUNE_TARGET_GB : 0, true);
}

void BpsApplication::createWindow(const NetworkStyle* network_style)
{
    m_window = new BpsWindow(node(), m_platform_style, network_style, nullptr);

    m_poll_shutdown_timer = new QTimer(m_window);
    connect(m_poll_shutdown_timer, &QTimer::timeout, m_window, &BpsWindow::detectShutdown);
}

void BpsApplication::createSplashScreen(const NetworkStyle* network_style)
{
    assert(!m_splash);
    m_splash = new SplashScreen(nullptr, network_style);
    m_splash->show();
    connect(this, &BpsApplication::requestedInitialize, m_splash, &SplashScreen::handleLoadWallet);
    connect(this, &BpsApplication::splashFinished, m_splash, &SplashScreen::finish);
    connect(this, &BpsApplication::requestedShutdown, m_splash, &QWidget::close);
}

void BpsApplication::setNode(interfaces::Node& node)
{
    assert(!m_node);
    m_node = &node;
    if (m_options_model) m_options_model->setNode(*m_node);
    if (m_splash) m_splash->setNode(*m_node);
}

bool BpsApplication::baseInitialize()
{
    return node().baseInitialize();
}

void BpsApplication::startThread()
{
    if (m_core_thread) return;
    m_core_thread = new QThread(this);

    // The wallet client's startup worker, used unchanged.
    BitcoinCore* executor = new BitcoinCore(node());
    executor->moveToThread(m_core_thread);

    connect(executor, &BitcoinCore::initializeResult, this, &BpsApplication::initializeResult);
    connect(executor, &BitcoinCore::shutdownResult, this, &BpsApplication::shutdownResult);
    connect(executor, &BitcoinCore::runawayException, this, &BpsApplication::handleRunawayException);
    connect(this, &BpsApplication::requestedInitialize, executor, &BitcoinCore::initialize);
    connect(this, &BpsApplication::requestedShutdown, executor, &BitcoinCore::shutdown);
    connect(m_core_thread, &QThread::finished, executor, &QObject::deleteLater);

    m_core_thread->start();
}

void BpsApplication::requestInitialize()
{
    startThread();
    Q_EMIT requestedInitialize();
}

void BpsApplication::requestShutdown()
{
    m_shutdown_window.reset(ShutdownWindow::showShutdownWindow(m_window));

    startThread();
    m_window->hide();
    // Must happen while an event loop is still running, or the thread deadlocks.
    m_window->unsubscribeFromCoreSignals();
    node().startShutdown();
    m_window->setClientModel(nullptr);
    m_poll_shutdown_timer->stop();

    delete m_client_model;
    m_client_model = nullptr;

    Q_EMIT requestedShutdown();
}

void BpsApplication::initializeResult(bool success, interfaces::BlockAndHeaderTipInfo tip_info)
{
    m_return_value = success ? EXIT_SUCCESS : EXIT_FAILURE;
    if (!success) {
        Q_EMIT splashFinished();
        quit();
        return;
    }

    qInfo() << "Platform customization:" << m_platform_style->getName();
    m_client_model = new ClientModel(node(), m_options_model);
    m_window->setClientModel(m_client_model, &tip_info);

#ifdef ENABLE_WALLET
    if (WalletModel::isWalletEnabled()) {
        m_wallet_controller = new WalletController(*m_client_model, m_platform_style, this);
        m_window->setWalletController(m_wallet_controller);
    }
#endif

    if (!gArgs.GetBoolArg("-min", false)) {
        m_window->show();
    } else {
        m_window->showMinimized();
    }
    Q_EMIT splashFinished();

    m_poll_shutdown_timer->start(200);
}

void BpsApplication::shutdownResult()
{
    quit();
}

void BpsApplication::handleRunawayException(const QString& message)
{
    QMessageBox::critical(
        nullptr, "Runaway exception",
        BpsWindow::tr("A fatal error occurred. %1 can no longer continue safely and will quit.").arg(GUIUtil::ClientName()) +
            QString("<br><br>") + message);
    ::exit(EXIT_FAILURE);
}

WId BpsApplication::getMainWinId() const
{
    return m_window ? m_window->winId() : 0;
}

static void SetupBpsUIArgs(ArgsManager& argsman)
{
    argsman.AddArg("-choosedatadir", strprintf("Choose data directory on startup (default: %u)", DEFAULT_CHOOSE_DATADIR), ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-lang=<lang>", "Set language, for example \"de_DE\" (default: system locale)", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-min", "Start minimized", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-resetguisettings", "Reset all settings changed in the GUI", ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-splash", strprintf("Show splash screen on startup (default: %u)", DEFAULT_SPLASHSCREEN), ArgsManager::ALLOW_ANY, OptionsCategory::GUI);
    argsman.AddArg("-uiplatform", strprintf("Select platform to customize UI for (one of windows, macosx, other; default: %s)", BitcoinGUI::DEFAULT_UIPLATFORM), ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::GUI);
}

int BpsGuiMain(int argc, char* argv[])
{
#ifdef WIN32
    util::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif
    SetupEnvironment();
    util::ThreadSetInternalName("main");

    NodeContext node_context;
    std::unique_ptr<interfaces::Node> node = interfaces::MakeNode(&node_context);

    boost::signals2::scoped_connection handler_message_box = ::uiInterface.ThreadSafeMessageBox_connect(noui_ThreadSafeMessageBox);
    boost::signals2::scoped_connection handler_question = ::uiInterface.ThreadSafeQuestion_connect(noui_ThreadSafeQuestion);
    boost::signals2::scoped_connection handler_init_message = ::uiInterface.InitMessage_connect(noui_InitMessage);

    // Icons, images and translations all come from the wallet client's bundles.
    Q_INIT_RESOURCE(bitcoin);
    Q_INIT_RESOURCE(bitcoin_locale);

    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#if QT_VERSION >= 0x050600
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif

    BpsApplication app;
    GUIUtil::SetClientName(BPS_CLIENT_NAME);

    SetupServerArgs(node_context);
    SetupBpsUIArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        InitError(strprintf(Untranslated("Error parsing command line arguments: %s\n"), error));
        QMessageBox::critical(nullptr, GUIUtil::ClientName(),
                              QString::fromStdString("Error parsing command line arguments: %1.").arg(QString::fromStdString(error)));
        return EXIT_FAILURE;
    }

    app.setupPlatformStyle();

    QApplication::setOrganizationName(QAPP_ORG_NAME);
    QApplication::setOrganizationDomain(QAPP_ORG_DOMAIN);
    QApplication::setApplicationName(BPS_APP_NAME);

    QTranslator qt_base, qt_locale, base, locale;
    InitTranslations(qt_base, qt_locale, base, locale);

    if (HelpRequested(gArgs) || gArgs.IsArgSet("-version")) {
        HelpMessageDialog help(nullptr, gArgs.IsArgSet("-version"));
        help.showOrPrint();
        return EXIT_SUCCESS;
    }

    app.installEventFilter(new GUIUtil::ToolTipToRichTextFilter(TOOLTIP_WRAP_THRESHOLD, &app));

    bool did_show_intro = false;
    bool prune = false;
    if (!Intro::showIfNeeded(did_show_intro, prune)) return EXIT_SUCCESS;

    if (!CheckDataDirOption()) {
        InitError(strprintf(Untranslated("Specified data directory \"%s\" does not exist.\n"), gArgs.GetArg("-datadir", "")));
        QMessageBox::critical(nullptr, GUIUtil::ClientName(),
                              QObject::tr("Error: Specified data directory \"%1\" does not exist.").arg(QString::fromStdString(gArgs.GetArg("-datadir", ""))));
        return EXIT_FAILURE;
    }
    if (!gArgs.ReadConfigFiles(error, true)) {
        InitError(strprintf(Untranslated("Error reading configuration file: %s\n"), error));
        QMessageBox::critical(nullptr, GUIUtil::ClientName(),
                              QObject::tr("Error: Cannot parse configuration file: %1.").arg(QString::fromStdString(error)));
        return EXIT_FAILURE;
    }

    try {
        SelectParams(gArgs.GetChainName());
    } catch (const std::exception& e) {
        InitError(Untranslated(strprintf("%s\n", e.what())));
        QMessageBox::critical(nullptr, GUIUtil::ClientName(), QObject::tr("Error: %1").arg(e.what()));
        return EXIT_FAILURE;
    }

    if (!gArgs.InitSettings(error)) {
        InitError(Untranslated(error));
        QMessageBox::critical(nullptr, GUIUtil::ClientName(), QObject::tr("Error initializing settings: %1").arg(QString::fromStdString(error)));
        return EXIT_FAILURE;
    }

    QScopedPointer<const NetworkStyle> network_style(NetworkStyle::instantiate(Params().NetworkIDString()));
    assert(!network_style.isNull());
    // Network-specific settings, still in this client's own namespace.
    QApplication::setApplicationName(QString(BPS_APP_NAME) + "-" + QString::fromStdString(Params().NetworkIDString()));
    InitTranslations(qt_base, qt_locale, base, locale);

    app.installEventFilter(new GUIUtil::LabelOutOfFocusEventFilter(&app));
    qInstallMessageHandler(DebugMessageHandler);
    app.parameterSetup();
    GUIUtil::LogQtInfo();
    app.createOptionsModel(gArgs.GetBoolArg("-resetguisettings", false));

    if (did_show_intro) app.InitializePruneSetting(prune);

    if (gArgs.GetBoolArg("-splash", DEFAULT_SPLASHSCREEN) && !gArgs.GetBoolArg("-min", false)) {
        app.createSplashScreen(network_style.data());
    }

    app.setNode(*node);

    int rv = EXIT_SUCCESS;
    try {
        app.createWindow(network_style.data());
        if (app.baseInitialize()) {
            app.requestInitialize();
            app.exec();
            app.requestShutdown();
            app.exec();
            rv = app.getReturnValue();
        } else {
            rv = EXIT_FAILURE;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "Runaway exception");
        app.handleRunawayException(QString::fromStdString(app.node().getWarnings().translated));
    } catch (...) {
        PrintExceptionContinue(nullptr, "Runaway exception");
        app.handleRunawayException(QString::fromStdString(app.node().getWarnings().translated));
    }
    return rv;
}

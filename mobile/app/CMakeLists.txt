# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# BPS Companion, the phone app: QML screens over ../core, the companion
# client built from the node's own sources. Written to the Qt 6.8 API so
# distributions' Qt builds it too; released with 6.12.

cmake_minimum_required(VERSION 3.21)
project(bps_companion_app VERSION 0.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.8 REQUIRED COMPONENTS Gui Qml Quick QuickControls2)
qt_standard_project_setup(REQUIRES 6.8)

set(BPS_COMPANION_CLI OFF CACHE BOOL "" FORCE)
add_subdirectory(../core core)

find_package(PkgConfig REQUIRED)
pkg_check_modules(QRENCODE REQUIRED IMPORTED_TARGET libqrencode)

qt_add_executable(bps-companion
  main.cpp
  backend.cpp
  backend.h
  qrprovider.cpp
  qrprovider.h)
target_include_directories(bps-companion PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

set_source_files_properties(qml/Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)
qt_add_qml_module(bps-companion
  URI BPSCompanion
  VERSION 1.0
  QML_FILES
    qml/Main.qml
    qml/Theme.qml
    qml/PrimaryButton.qml
    qml/QuietButton.qml
    qml/Field.qml
    qml/PinPad.qml
    qml/PageTitle.qml
    qml/HistoryList.qml
    qml/PairPage.qml
    qml/PinPage.qml
    qml/CodePage.qml
    qml/HomePage.qml
    qml/SendPage.qml
    qml/ReviewPage.qml
    qml/SentPage.qml
    qml/ReceivePage.qml
    qml/ActivityPage.qml
    qml/SettingsPage.qml
    qml/LockedPage.qml)

target_link_libraries(bps-companion PRIVATE
  Qt6::Gui Qt6::Qml Qt6::Quick Qt6::QuickControls2
  bps_companion_core PkgConfig::QRENCODE)

install(TARGETS bps-companion RUNTIME DESTINATION bin)

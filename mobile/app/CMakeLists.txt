# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# BPS Companion, the phone app: QML screens over ../core, the companion
# client built from the node's own sources. Written to the Qt 6.8 API so
# distributions' Qt builds it too; released with 6.12.

cmake_minimum_required(VERSION 3.21)
project(bps_companion_app VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.8 REQUIRED COMPONENTS Concurrent Gui Multimedia Qml Quick QuickControls2)
# QR codes read and drawn with ZXing-C++; the device key kept by QtKeychain.
find_package(ZXing 3 REQUIRED)
find_package(Qt6Keychain REQUIRED)
qt_standard_project_setup(REQUIRES 6.8)

set(BPS_COMPANION_CLI OFF CACHE BOOL "" FORCE)
add_subdirectory(../core core)

qt_add_executable(bps-companion
  main.cpp
  backend.cpp
  backend.h
  devicekey.cpp
  devicekey.h
  qrprovider.cpp
  qrprovider.h)
target_include_directories(bps-companion PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

set_source_files_properties(qml/Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)
# Choosing a picture of a code: the system's picker on a phone, Qt's dialog
# elsewhere. QtQuick.Dialogs brings every Controls style along, about 20 MB
# a phone would carry for nothing.
if(ANDROID)
  set(picture_sources androidpicker.cpp androidpicker.h)
  set(picture_qml platform/android/PictureDialog.qml)
else()
  set(picture_sources)
  set(picture_qml platform/desktop/PictureDialog.qml)
endif()
set_source_files_properties(${picture_qml} PROPERTIES QT_RESOURCE_ALIAS PictureDialog.qml)
qt_add_qml_module(bps-companion
  URI BPSCompanion
  VERSION 1.0
  SOURCES
    qrscanner.cpp
    qrscanner.h
    ${picture_sources}
  QML_FILES
    ${picture_qml}
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
    qml/LockedPage.qml
    qml/ScanPage.qml)

target_link_libraries(bps-companion PRIVATE
  Qt6::Concurrent Qt6::Gui Qt6::Multimedia Qt6::Qml Qt6::Quick Qt6::QuickControls2
  ZXing::ZXing Qt6Keychain::Qt6Keychain
  bps_companion_core)

if(ANDROID)
  # Android 9 and later; Qt's own floor for 6.12 too.
  set_target_properties(bps-companion PROPERTIES
    QT_ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android"
    QT_ANDROID_PACKAGE_NAME org.bps.companion
    QT_ANDROID_APP_NAME "BPS Companion"
    QT_ANDROID_MIN_SDK_VERSION 28
    QT_ANDROID_TARGET_SDK_VERSION 36
    QT_ANDROID_VERSION_NAME "${PROJECT_VERSION}"
    QT_ANDROID_VERSION_CODE 1
    # Libraries compressed in the package: a much smaller download, which is
    # what matters for a package fetched by hand or from F-Droid.
    QT_ANDROID_LEGACY_PACKAGING ON)
  # QML debugger and profiler plugins, and image formats no code arrives in.
  qt_import_plugins(bps-companion EXCLUDE_BY_TYPE qmltooling iconengines
    EXCLUDE Qt6::QGifPlugin Qt6::QICOPlugin)
  # The activity-result hook the picker uses.
  find_package(Qt6 REQUIRED COMPONENTS CorePrivate)
  target_link_libraries(bps-companion PRIVATE Qt6::CorePrivate)
  # The client's own UDP socket is not Qt Network's, so nothing adds this by itself.
  qt_add_android_permission(bps-companion NAME android.permission.INTERNET)
  qt_add_android_permission(bps-companion NAME android.permission.CAMERA)
else()
  install(TARGETS bps-companion RUNTIME DESTINATION bin)
  if(UNIX AND NOT APPLE)
    # A launcher, an icon and the description software centres show.
    install(FILES linux/org.bps.companion.desktop DESTINATION share/applications)
    install(FILES linux/org.bps.companion.metainfo.xml DESTINATION share/metainfo)
    install(FILES linux/org.bps.companion.svg DESTINATION share/icons/hicolor/scalable/apps)
  endif()
endif()

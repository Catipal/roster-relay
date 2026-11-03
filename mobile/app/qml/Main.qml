import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

ApplicationWindow {
    id: window
    width: 390
    height: 844
    visible: true
    title: qsTr("BPS Companion")
    color: Theme.background
    font.pixelSize: 15

    // Where the screens are: pairing first, then the four tabs and the steps of a payment.
    property string screen: backend.state === "paired" ? "home" : "pair"
    property string firstPin: ""
    property string scanFor: ""   // "ticket" or "payee"
    readonly property var tabs: ["home", "activity", "receive", "settings"]
    readonly property var pages: ["pair", "pin", "code", "locked", "home", "send", "review", "sent",
                                  "receive", "activity", "settings", "broken", "scan"]

    function go(name) {
        backend.clearError()
        screen = name
        if (name === "receive" && backend.address === "") backend.newAddress()
        else if (name === "activity") backend.loadHistory()
    }

    readonly property string shown: startupError !== "" ? "broken"
        : backend.state === "waiting" ? "code"
        : backend.state === "locked" ? "locked"
        : backend.state === "unpaired" ? (screen === "pin" || screen === "scan" ? screen : "pair")
        : (screen === "pair" || screen === "pin" ? "home" : screen)

    function startScan(what) {
        scanFor = what
        scanPage.title = what === "ticket" ? qsTr("Scan the home node's code") : qsTr("Scan an address")
        screen = "scan"
        scanPage.start()
    }

    // An address as text, or as a payment link: bps:<address>?amount=<coins>
    function takePayee(text) {
        let t = text.trim()
        const colon = t.indexOf(":")
        if (colon > 0 && colon < 8) t = t.slice(colon + 1)
        const q = t.indexOf("?")
        if (q >= 0) {
            const m = t.slice(q + 1).match(/(?:^|&)amount=([0-9.]+)/)
            if (m) sendPage.amount = m[1]
            t = t.slice(0, q)
        }
        sendPage.to = t
    }

    Connections {
        target: backend
        function onStateChanged() {
            if (backend.state === "paired") window.screen = "home"
            else if (backend.state === "unpaired") { window.screen = "pair"; pinPage.confirming = false; pinPage.reset() }
        }
        function onPreparedReady() { reviewPage.reset(); window.screen = "review" }
        function onSendDone() { sendPage.to = ""; sendPage.amount = ""; window.screen = "sent" }
    }

    // Until the home node accepts, ask every few seconds.
    Timer {
        interval: 3000
        repeat: true
        running: backend.state === "waiting"
        triggeredOnStart: true
        onTriggered: backend.pollPairing()
    }

    Component.onCompleted: if (backend.state === "paired" || backend.state === "locked") backend.refresh()

    // Coming back to the app is a good moment to look again.
    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.application.state === Qt.ApplicationActive && backend.state === "paired") backend.refresh()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: window.pages.indexOf(window.shown)

            PairPage {
                id: pairPage
                onScan: window.startScan("ticket")
                onNext: { pinPage.confirming = false; pinPage.problem = ""; pinPage.reset(); window.screen = "pin" }
            }
            PinPage {
                id: pinPage
                working: backend.busy
                onBack: {
                    if (confirming) { confirming = false; problem = ""; reset() }
                    else window.screen = "pair"
                }
                onChosen: (pin) => {
                    if (!confirming) {
                        window.firstPin = pin
                        confirming = true
                        problem = ""
                        reset()
                    } else if (pin !== window.firstPin) {
                        confirming = false
                        problem = qsTr("The two PINs differ. Choose one again.")
                        reset()
                    } else {
                        window.firstPin = ""
                        // A refusal comes back as the state "unpaired": the first screen, with the error.
                        backend.pair(pairPage.ticket, pairPage.phoneName, pin)
                    }
                }
            }
            Item {
                CodePage {
                    anchors.fill: parent
                    anchors.margins: Theme.gutter
                    onGiveUp: backend.forget()
                }
            }
            Item {
                LockedPage { anchors.fill: parent; anchors.margins: Theme.gutter }
            }
            HomePage {
                onSend: window.go("send")
                onReceive: window.go("receive")
                onActivity: window.go("activity")
            }
            Item {
                SendPage {
                    id: sendPage
                    anchors.fill: parent
                    anchors.margins: Theme.gutter
                    anchors.topMargin: 16
                    onBack: window.go("home")
                    onScan: window.startScan("payee")
                }
            }
            Item {
                ReviewPage {
                    id: reviewPage
                    anchors.fill: parent
                    anchors.margins: Theme.gutter
                    anchors.topMargin: 16
                    onBack: { backend.cancel(); window.go("send") }
                }
            }
            Item {
                SentPage { anchors.fill: parent; anchors.margins: Theme.gutter; onDone: window.go("home") }
            }
            Item {
                ReceivePage { anchors.fill: parent; anchors.margins: Theme.gutter; anchors.topMargin: 24 }
            }
            ActivityPage {}
            SettingsPage { id: settingsPage }
            Item {
                Label {
                    anchors.fill: parent
                    anchors.margins: Theme.gutter
                    text: startupError
                    color: Theme.danger
                    wrapMode: Text.Wrap
                    verticalAlignment: Text.AlignVCenter
                }
            }
            ScanPage {
                id: scanPage
                onBack: window.screen = window.scanFor === "ticket" ? "pair" : "send"
                onScanned: (text) => {
                    if (window.scanFor === "ticket") {
                        pairPage.ticket = text
                        window.screen = "pair"
                    } else {
                        window.takePayee(text)
                        window.screen = "send"
                    }
                }
            }
        }

        // The tabs, once paired and outside a payment.
        Rectangle {
            visible: window.tabs.indexOf(window.shown) >= 0
            Layout.fillWidth: true
            implicitHeight: 64
            color: Theme.surface
            Rectangle { width: parent.width; height: 1; color: Theme.line }
            RowLayout {
                anchors.fill: parent
                spacing: 0
                Repeater {
                    model: [
                        { name: "home", label: qsTr("Home") },
                        { name: "activity", label: qsTr("Activity") },
                        { name: "receive", label: qsTr("Receive") },
                        { name: "settings", label: qsTr("Settings") }
                    ]
                    ToolButton {
                        id: tab
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        text: modelData.label
                        font.pixelSize: 13
                        font.weight: window.shown === modelData.name ? Font.Bold : Font.Normal
                        contentItem: Text {
                            text: tab.text
                            font: tab.font
                            color: window.shown === modelData.name ? Theme.accent : Theme.muted
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        background: Item {}
                        onClicked: { settingsPage.confirming = false; window.go(modelData.name) }
                    }
                }
            }
        }
    }
}

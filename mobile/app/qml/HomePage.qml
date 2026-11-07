import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

Flickable {
    id: root
    signal send()
    signal receive()
    signal activity()
    contentHeight: column.implicitHeight + 48
    clip: true

    ColumnLayout {
        id: column
        x: Theme.gutter
        y: 24
        width: root.width - 2 * Theme.gutter
        spacing: 16

        RowLayout {
            Layout.fillWidth: true
            ColumnLayout {
                spacing: 2
                Layout.fillWidth: true
                Label { text: qsTr("Home node"); font.pixelSize: 13; color: Theme.muted }
                Label {
                    text: backend.homeNode + (backend.network !== "main" ? "  ·  " + backend.network : "")
                    font.family: Theme.mono
                    font.pixelSize: 13
                    color: Theme.text
                }
            }
            Label {
                text: backend.busy ? qsTr("asking…")
                    : backend.status.reached ? qsTr("reached at %1").arg(backend.status.reached)
                    : qsTr("not reached")
                font.pixelSize: 13
                color: backend.status.reached ? Theme.good : Theme.muted
            }
        }

        Rectangle {
            Layout.fillWidth: true
            implicitHeight: card.implicitHeight + 40
            radius: 20
            color: Theme.accent
            ColumnLayout {
                id: card
                anchors.fill: parent
                anchors.margins: 20
                spacing: 14
                ColumnLayout {
                    spacing: 2
                    Layout.fillWidth: true
                    Label { text: qsTr("Allowance"); color: "#D6E6F5"; font.pixelSize: 14 }
                    Label {
                        // Shrinks rather than widen the card when a balance has every decimal.
                        text: (backend.status.walletProblem ? "—" : (backend.status.balance || "—")) + " BPS"
                        color: "white"
                        font.pixelSize: 34
                        font.weight: Font.Bold
                        fontSizeMode: Text.HorizontalFit
                        minimumPixelSize: 18
                        Layout.fillWidth: true
                        Layout.preferredWidth: 0
                    }
                    Label {
                        visible: !!backend.status.hasPending
                        text: qsTr("%1 BPS on its way").arg(backend.status.pending)
                        color: "#D6E6F5"
                        font.pixelSize: 13
                    }
                }
                ColumnLayout {
                    spacing: 6
                    Layout.fillWidth: true
                    RowLayout {
                        Layout.fillWidth: true
                        Label { text: qsTr("Left today"); color: "white"; font.pixelSize: 14; Layout.fillWidth: true }
                        Label {
                            text: qsTr("%1 of %2").arg(backend.status.leftToday || "—").arg(backend.status.perDay || "—")
                            color: "white"
                            font.pixelSize: 14
                        }
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: 6
                        radius: 3
                        color: "#4D8CC4"
                        Rectangle {
                            width: parent.width * (backend.status.leftFraction || 0)
                            height: parent.height
                            radius: 3
                            color: "white"
                        }
                    }
                    Label {
                        text: qsTr("Up to %1 BPS in one payment").arg(backend.status.perTx || "—")
                        color: "#D6E6F5"
                        font.pixelSize: 13
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            PrimaryButton { text: qsTr("Send"); Layout.fillWidth: true; onClicked: root.send() }
            QuietButton { text: qsTr("Receive"); Layout.fillWidth: true; onClicked: root.receive() }
        }

        Label {
            visible: backend.error !== ""
            text: backend.error
            color: Theme.danger
            font.pixelSize: 14
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        Label {
            visible: !!backend.status.walletProblem && backend.error === ""
            text: qsTr("Your home node cannot pay or be paid yet: %1 Create the allowance wallet on its Server page, then top it up.").arg(backend.status.walletProblem || "")
            color: Theme.danger
            font.pixelSize: 14
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        Label {
            visible: backend.direct && backend.error === ""
            text: qsTr("Connected straight to your home node, with no relays in between: this phone's network can see it talks to that node.")
            color: Theme.muted
            font.pixelSize: 13
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 8
            Label { text: qsTr("Recent"); font.pixelSize: 18; font.weight: Font.Bold; color: Theme.text; Layout.fillWidth: true }
            QuietButton { flat: true; tint: Theme.accent; text: qsTr("All activity"); onClicked: root.activity() }
        }
        HistoryList {
            Layout.fillWidth: true
            items: backend.history.slice(0, 3)
        }
        QuietButton {
            text: qsTr("Refresh")
            enabled: !backend.busy
            Layout.fillWidth: true
            onClicked: backend.refresh()
        }
    }
}

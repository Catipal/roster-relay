import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

Flickable {
    id: root
    contentHeight: column.implicitHeight + 48
    clip: true

    ColumnLayout {
        id: column
        x: Theme.gutter
        y: 24
        width: root.width - 2 * Theme.gutter
        spacing: 16

        PageTitle { text: qsTr("Activity"); Layout.fillWidth: true }
        HistoryList { items: backend.history; Layout.fillWidth: true }
        Label {
            text: qsTr("Only payments from and to the allowance wallet show here. The rest of your coins stay on the home node and never appear on this phone.")
            color: Theme.muted
            font.pixelSize: 13
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }
}

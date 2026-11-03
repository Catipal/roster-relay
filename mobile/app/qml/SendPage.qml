import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

ColumnLayout {
    id: root
    property alias to: toField.text
    property alias amount: amountField.text
    signal back()
    spacing: 20

    PageTitle { text: qsTr("Send"); back: true; onBackClicked: root.back(); Layout.fillWidth: true }

    Field {
        id: toField
        label: qsTr("To an address or a name")
        placeholder: qsTr("bob, or an address")
        inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
        Layout.fillWidth: true
    }
    Field {
        id: amountField
        label: qsTr("Amount, BPS")
        placeholder: "0.00"
        inputMethodHints: Qt.ImhFormattedNumbersOnly
        note: backend.status.perTx ? qsTr("Up to %1 BPS in one payment, %2 BPS left today.")
                                         .arg(backend.status.perTx).arg(backend.status.leftToday) : ""
        Layout.fillWidth: true
    }
    Label {
        visible: backend.error !== ""
        text: backend.error
        color: Theme.danger
        font.pixelSize: 14
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Item { Layout.fillHeight: true }
    BusyIndicator { visible: backend.busy; running: visible; Layout.alignment: Qt.AlignHCenter }
    PrimaryButton {
        text: qsTr("Review")
        enabled: !backend.busy && toField.text.trim() !== "" && backend.validAmount(amountField.text)
        Layout.fillWidth: true
        onClicked: backend.prepare(toField.text, amountField.text)
    }
}

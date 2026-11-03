import QtCore
import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Dialogs
import QtQuick.Layouts
import QtMultimedia

// The camera, looking for a QR code; or a picture of one, where there is no camera.
Item {
    id: root
    property string title: qsTr("Scan the code")
    property bool scanning: false
    signal scanned(string text)
    signal back()

    property string problem: ""

    function start() {
        problem = ""
        scanner.reset()
        if (permission.status === Qt.PermissionStatus.Undetermined) permission.request()
        scanning = true
    }
    function stop() { scanning = false }

    readonly property bool haveCamera: devices.videoInputs.length > 0
    readonly property bool allowed: permission.status === Qt.PermissionStatus.Granted

    CameraPermission { id: permission }
    MediaDevices { id: devices }

    CaptureSession {
        camera: Camera {
            id: camera
            active: root.scanning && root.allowed && root.haveCamera
            focusMode: Camera.FocusModeAutoNear
        }
        videoOutput: output
    }

    QrScanner {
        id: scanner
        videoSink: output.videoSink
        onFound: (text) => { root.scanning = false; root.scanned(text) }
    }

    FileDialog {
        id: picture
        title: qsTr("A picture of the code")
        nameFilters: [qsTr("Pictures (*.png *.jpg *.jpeg *.webp *.bmp)")]
        onAccepted: {
            const text = scanner.decodeFile(selectedFile)
            if (text === "") root.problem = qsTr("No QR code found in that picture.")
            else { root.scanning = false; root.scanned(text) }
        }
    }

    Rectangle { anchors.fill: parent; color: "#0E1620" }

    VideoOutput {
        id: output
        anchors.fill: parent
        fillMode: VideoOutput.PreserveAspectCrop
        visible: camera.active
    }

    // The square to aim at.
    Rectangle {
        visible: camera.active
        anchors.centerIn: parent
        width: Math.min(parent.width, parent.height) * 0.7
        height: width
        radius: 20
        color: "transparent"
        border.width: 3
        border.color: "white"
        opacity: 0.85
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.gutter
        anchors.topMargin: 16
        spacing: 16

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            ToolButton {
                text: "←"
                font.pixelSize: 22
                implicitWidth: 44
                implicitHeight: 44
                Accessible.name: qsTr("Back")
                contentItem: Text { text: parent.text; font: parent.font; color: "white"; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
                background: Item {}
                onClicked: { root.scanning = false; root.back() }
            }
            Label { text: root.title; color: "white"; font.pixelSize: 20; font.weight: Font.Bold; elide: Text.ElideRight; Layout.fillWidth: true }
        }

        Item { Layout.fillHeight: true }

        Label {
            visible: !camera.active
            text: !root.haveCamera ? qsTr("No camera here. Choose a picture of the code instead.")
                : permission.status === Qt.PermissionStatus.Denied
                    ? qsTr("The camera is not allowed for this app. Allow it in the phone's settings, or choose a picture of the code.")
                    : qsTr("Starting the camera…")
            color: "white"
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
        }
        Label {
            visible: root.problem !== ""
            text: root.problem
            color: "#FFB4AB"
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
        }

        Item { Layout.fillHeight: true }

        QuietButton {
            text: qsTr("Choose a picture instead")
            Layout.fillWidth: true
            onClicked: picture.open()
        }
    }
}

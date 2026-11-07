import QtCore
import QtQuick
import QtQuick.Controls.Basic
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

    readonly property bool allowed: permission.status === Qt.PermissionStatus.Granted
    // Asked only once the camera is allowed: on Android, Qt lists no cameras
    // before that and keeps the empty list for as long as the app runs.
    readonly property bool haveCamera: allowed && devices.videoInputs.length > 0
    readonly property bool cameraOn: session.item ? session.item.on : false

    CameraPermission { id: permission }
    MediaDevices { id: devices }

    // Back from the phone's settings, where the camera may just have been
    // allowed: ask again, which answers at once when it was.
    Connections {
        target: Qt.application
        function onStateChanged() {
            if (Qt.application.state === Qt.ApplicationActive && root.scanning && !root.allowed) permission.request()
        }
    }

    // Made only once allowed, for the same reason: a camera made before then
    // asks for the list, and finds nothing for good.
    Loader {
        id: session
        active: root.allowed
        sourceComponent: Item {
            readonly property bool on: camera.active
            CaptureSession {
                camera: Camera {
                    id: camera
                    active: root.scanning && root.haveCamera
                    focusMode: Camera.FocusModeAutoNear
                }
                videoOutput: output
            }
        }
    }

    QrScanner {
        id: scanner
        videoSink: output.videoSink
        onFound: (text) => { root.scanning = false; root.scanned(text) }
    }

    PictureDialog {
        id: picture
        onPicked: (url) => {
            const text = scanner.decodeFile(url)
            if (text === "") root.problem = qsTr("No QR code found in that picture.")
            else { root.scanning = false; root.scanned(text) }
        }
    }

    Rectangle { anchors.fill: parent; color: "#0E1620" }

    VideoOutput {
        id: output
        anchors.fill: parent
        fillMode: VideoOutput.PreserveAspectCrop
        visible: root.cameraOn
    }

    // The square to aim at.
    Rectangle {
        visible: root.cameraOn
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
            visible: !root.cameraOn
            text: permission.status === Qt.PermissionStatus.Denied
                    ? qsTr("The camera is not allowed for this app. Allow it in the phone's settings, or choose a picture of the code.")
                : !root.allowed ? qsTr("Waiting for permission to use the camera…")
                : !root.haveCamera ? qsTr("No camera here. Choose a picture of the code instead.")
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

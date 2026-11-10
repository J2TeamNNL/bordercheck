package notify

import "context"

// Windows: a toast through the WinRT API in Windows PowerShell 5.1, which every
// Windows 10 and 11 ships with; no admin rights. The toast is posted under
// Windows PowerShell's own app ID, since an unregistered app ID shows nothing.
// The text goes in as environment variables and is XML-escaped by the script,
// so nothing in it can run as code or break the toast XML. The scheduled task
// runs only while the user is logged on, so the toast lands on their desktop.
const toastScript = `$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$t = [Security.SecurityElement]::Escape($env:BORDERCHECK_NOTIFY_TITLE)
$b = [Security.SecurityElement]::Escape($env:BORDERCHECK_NOTIFY_BODY)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))`

func show(ctx context.Context, m Message) error {
	return run(ctx, []string{"BORDERCHECK_NOTIFY_TITLE=" + m.Title, "BORDERCHECK_NOTIFY_BODY=" + m.Body},
		"powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", toastScript)
}

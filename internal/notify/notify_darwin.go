package notify

import "context"

// macOS: AppleScript's display notification, through osascript. The text goes
// in as arguments, never into the script, so nothing in it can run as code.
// From the LaunchAgent it shows in the user's session; macOS lists it under
// Script Editor in System Settings → Notifications.
const appleScript = `on run argv
	display notification (item 2 of argv) with title (item 1 of argv)
end run`

func show(ctx context.Context, m Message) error {
	return run(ctx, nil, "/usr/bin/osascript", "-e", appleScript, m.Title, m.Body)
}

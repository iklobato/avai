# macOS elevation: deferred to a privileged helper

You chose "force-elevate the whole app every launch." On Windows that is a
clean UAC manifest. On macOS it is not possible for a notarized GUI `.app`:
Apple has no supported way to run a whole GUI app as root, and the old
admin-relaunch API is deprecated. Running the GUI as root would also fail
notarization in practice and is an anti-pattern.

**v1 ships the mac app unprivileged.** The root-only collectors (tcpdump DNS,
socket->process mapping, `eslogger` exec events) silently skip; everything else
works. This is the honest, signable starting point.

**Upgrade path (the real "full collectors on mac"):**
the GUI stays unprivileged and registers a privileged **monitor helper** via
`SMAppService` (the modern replacement for `SMJobBless`). The helper:
- is a separate, signed + notarized bundle shipped inside `avai.app`,
- runs the monitor (`build_runner` + `run_forever`) as root under launchd,
- talks to the GUI over XPC (no subprocess), writing the same `~/.avai/avai.db`.

This needs a Mac + Xcode to build and sign the helper, so it is a follow-up,
not part of the unsigned/Releases-first v1. Same end result (full collectors),
without running the window as root.

# Changelog

## 0.11.0

- `run` can record the child PID, start tick, host duration and exit receipt. It preserves ambiguous shell statuses and reports the wrapper timeout separately.
- `kernel_snapshot` captures boot identity, bounded dmesg and pstore records with SHA-256 hashes. It reports permission, disconnect and source errors separately.
- `kernel_record` records module identity and state before and after the requested actions. Loading and unloading require explicit flags and Root. Module parameters are sent as individual arguments.

## 0.10.0

- Compare declared permissions, SDK levels, application settings, components and their intent filters in APK inventories.
- Use the English README on the npm package page and link to the Simplified Chinese translation under `docs/`.

## 0.9.1

- Fixed the Simplified Chinese README link on npm and made the terminal examples visible in both READMEs.

## 0.9.0

- Added single-step taps and long presses by exact UI selector.
- Added replay progress and cancellation, long presses, and waits and assertions for absent controls.
- Added native load diagnosis for installed apps and supplied APK sets. Checks include missing dependencies, ABI mismatches, and 16 KB APK and ELF alignment.
- Added signed native diagnostic fixtures and a verifier that reproduces a real linker failure.
- Added a standalone npm package for the host server, with per-user report storage.

## 0.8.2

- Verify Shizuku connections by reading the Android execution identity.
- Preserve binary output through rish so Device Use screenshots survive terminal line-ending conversion.
- Allow the same Device Use replay verifier to exercise Shizuku over ADB. Check screenshots and UI trees, exact Unicode, and interruption when the Shizuku service stops.

## 0.8.1

- Separate source distribution and cross-platform build instructions.
- Updated transitive dependencies in the npm lockfile.
- Device Use distinguishes a lock or foreground change when UI Automator is interrupted during sampling.
- Added a repeatable Android replay verifier and retained the shared eight-step test flow.
- Paired USB config supports a per-user location and config-relative certificate paths.
- Concurrent pairing commands cannot overwrite one another's credentials.

## 0.8.0

- Added versioned JSON UI replays, resource selectors, waits, assertions and scroll-to-find. Failed runs retain a local report and available evidence.

## 0.7.2

- Added optional Unicode input for Device Use with a user-selected Android input method.

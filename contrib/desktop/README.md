# Desktop launcher (not part of Hot-Stream's build output)

## What this is

`install.sh` sets up Hot-Stream so it can be launched from an application menu/launcher —
normal desktop use, with no `npm`/`cargo`/`tauri` command ever needed again. Like
`contrib/system/`, this is a manually-run, documented script, not something Hot-Stream
installs itself, and it changes nothing under the project checkout.

## Why a script instead of `tauri build`'s own Linux bundlers

Tauri can produce a `.deb`, an `.rpm`, or an AppImage — but each needs its own packaging tool
(`dpkg-deb`, `rpmbuild`, `appimagetool`) present on the machine building it, and none of those
are installed here (confirmed directly: `tauri build --bundles deb,appimage` fails at the
bundling step for exactly that reason, after a successful compile). Arch Linux's own native
format is a PKGBUILD, which Tauri's bundler does not produce at all. Rather than requiring the
user to install extra system packaging tools just to try Hot-Stream, this script does the
same job — real binaries and a real launcher entry, findable in the same launcher/menu users
already use — directly with `install(1)` into standard per-user XDG locations, needing no root
for anything except the one capability grant that was always going to need it.

## What it does, precisely

- Copies the already-built `hot-stream` and `hot-stream-helper` release binaries into
  `~/.local/bin`.
- Copies the app icon into `~/.local/share/icons/hicolor/128x128/apps`.
- Writes a `.desktop` entry into `~/.local/share/applications` pointing at the copied binary,
  and refreshes the desktop/icon caches if the tools to do so (`update-desktop-database`,
  `gtk-update-icon-cache`) are present — harmless no-ops if not; most launchers pick up a new
  `.desktop` file on their own regardless.
- Prints, but never itself runs, the one-time `sudo setcap cap_net_admin+eip
  ~/.local/bin/hot-stream-helper` step Block/bandwidth-limit enforcement needs. Hot-Stream's
  own engineering rule throughout this project is that nothing here ever invokes `sudo` on the
  user's behalf — the same reasoning as `contrib/system/`'s README.

It does not build anything — build first (see the script's own header, or the main project
instructions).

## The WebKit rendering workaround needs no special handling here

`WEBKIT_DISABLE_DMABUF_RENDERER=1` (needed under Hyprland/Wayland on this machine — see
CLAUDE.md) is set programmatically in `src-tauri/src/main.rs`, before any window is created,
unless the user has already set the variable themselves. The `.desktop` entry's plain
`Exec=.../hot-stream` therefore does not need to set it, and neither does anything launching
the binary directly.

## Install

```sh
cd <repo>
npm install && npm run build
(cd src-tauri && cargo build --release --bins)
./contrib/desktop/install.sh
```

## Remove

```sh
rm -f ~/.local/bin/hot-stream ~/.local/bin/hot-stream-helper
rm -f ~/.local/share/applications/hot-stream.desktop
rm -f ~/.local/share/icons/hicolor/128x128/apps/hot-stream.png
```

(The `sudo setcap` grant lives on the binary file itself — removing the file removes it too;
nothing separate to undo.)

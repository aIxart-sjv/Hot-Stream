fn main() {
    // WebKitGTK's DMA-BUF renderer gives a blank window under Hyprland/Wayland on this
    // machine. Disable it unless the user has already set the variable themselves
    // (e.g. `WEBKIT_DISABLE_DMABUF_RENDERER=0` to re-enable). This must happen before any
    // thread is spawned, i.e. before `run()`.
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    hot_stream_lib::run()
}

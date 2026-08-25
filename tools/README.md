# tools/

Build-time helpers. Nothing here is imported by `attenu_guard` or by the
test suite, and nothing here needs network access.

## `render_demo_gif.py` — regenerate `docs/assets/demo.gif`

Runs the library's own `attenu-guard demo` and replays its output as a terminal-recording
GIF (960x620, 100x28 character grid, per-frame timing, auto-scrolling).

```bash
pip install pillow                  # required
python tools/render_demo_gif.py     # writes docs/assets/demo.gif
```

Re-run it whenever the demo's output changes so the GIF stays honest — it is
rendered *from* the real command, never hand-edited. `ffmpeg` is optional: it is
only tried as an alternate encoder if the Pillow-encoded GIF exceeds the size
budget. Useful flags: `--out PATH`, `--budget BYTES` (default 2,500,000),
`--encoder {auto,pillow,ffmpeg}`, `--dump-frames DIR` (write first/middle/last
frames as PNGs for eyeballing).

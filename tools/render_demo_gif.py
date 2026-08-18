#!/usr/bin/env python3
"""Render the README demo GIF for delegation-guard.

Runs the library's own demo (`dg demo` / `python -m delegation_guard.cli demo`),
captures its plain-text output, and replays it as a terminal-recording-style
animated GIF at ``docs/assets/demo.gif``.

Usage
-----
    python tools/render_demo_gif.py [--out docs/assets/demo.gif]

Requirements
------------
    pip install pillow          # required (frame rendering)
    ffmpeg                      # OPTIONAL; used only as an alternate encoder
                                # when the Pillow-encoded GIF exceeds --budget

Notes
-----
* Fully offline: no network access, no third-party services.
* This module is a build tool. It is NOT imported by the library or the tests
  and nothing under ``src/`` depends on it.
* Deterministic apart from the demo's own output: re-running regenerates a
  byte-comparable GIF.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - tool-only dependency
    sys.exit("render_demo_gif.py needs Pillow:  pip install pillow")


# --------------------------------------------------------------------------
# Geometry.  960 x 620 px, a 100-column x 28-row terminal in Menlo 15.
# --------------------------------------------------------------------------
FRAME_W = 960
TITLE_H = 32
PAD_X = 28
PAD_TOP = 12
PAD_BOTTOM = 16
FONT_SIZE = 15
CHROME_FONT_SIZE = 12
LINE_H = 20
ROWS = 28
FRAME_H = TITLE_H + PAD_TOP + ROWS * LINE_H + PAD_BOTTOM  # 620

# --------------------------------------------------------------------------
# Timing (milliseconds).  Encoded per frame, so durations really do vary.
# --------------------------------------------------------------------------
MS_PER_CHAR = 40        # typing the prompt
MS_AFTER_ENTER = 520    # beat between RETURN and the first output line
MS_PER_LINE = 110       # each revealed output line
MS_PER_BLANK = 45       # blank lines go by faster
MS_STEP_PAUSE = 600     # extra hold at the end of each [n] block
MS_FINAL_HOLD = 2500    # hold on the last frame before the loop restarts

PROMPT = "$ "
COMMAND = "dg demo"

# --------------------------------------------------------------------------
# Palette (GitHub-dark-ish).
# --------------------------------------------------------------------------
BG = "#0d1117"
CHROME_BG = "#161b22"
CHROME_LINE = "#30363d"
CHROME_TEXT = "#7d8590"
DOT_RED, DOT_YELLOW, DOT_GREEN = "#ff5f56", "#ffbd2e", "#27c93f"
CURSOR = "#c9d1d9"

STYLES = {
    #  name        colour      bold
    "dim":       ("#3d444d", False),   # ==== banner rules
    "title":     ("#e6edf3", True),    # banner headline
    "text":      ("#c9d1d9", False),   # everything else: light grey
    "step_num":  ("#58a6ff", True),    # the "[n]" itself
    "step":      ("#e6edf3", True),    # the rest of an [n] header
    "ok":        ("#3fb950", True),    # ALLOWED / verified
    "ok_body":   ("#56d364", False),
    "bad":       ("#f85149", True),    # BLOCKED / raised AuthorityDenied
    "bad_body":  ("#ff9d8a", False),   # the denial reason, softer orange
    "warn":      ("#d29922", False),   # cascade-revoked
    "prompt":    ("#58a6ff", True),
    "cmd":       ("#e6edf3", True),
}

FONT_CANDIDATES = [
    ("/System/Library/Fonts/Menlo.ttc", 0, 1),
    ("/System/Library/Fonts/Monaco.ttf", 0, 0),
    ("/System/Library/Fonts/SFNSMono.ttf", 0, 0),
    ("/Library/Fonts/Courier New.ttf", 0, 0),
    ("/System/Library/Fonts/Courier.ttc", 0, 1),
]

STEP_RE = re.compile(r"^(\s*)(\[\d+\])(.*)$")
CHECK, CROSS = "✓", "✗"


# ==========================================================================
# Font selection
# ==========================================================================
def _has_ink(font, ch: str) -> bool:
    probe = Image.new("L", (48, 48), 0)
    ImageDraw.Draw(probe).text((6, 6), ch, font=font, fill=255)
    return probe.getbbox() is not None


def pick_font():
    """Return (regular, bold, chrome, char_w, name, glyphs_ok)."""
    for path, reg_idx, bold_idx in FONT_CANDIDATES:
        if not Path(path).exists():
            continue
        try:
            regular = ImageFont.truetype(path, FONT_SIZE, index=reg_idx)
            bold = ImageFont.truetype(path, FONT_SIZE, index=bold_idx)
            chrome = ImageFont.truetype(path, CHROME_FONT_SIZE, index=reg_idx)
        except OSError:
            continue
        width = regular.getlength("M")
        if any(abs(regular.getlength(c) - width) > 0.05 for c in "MiW.$[]=/'"):
            continue  # not actually monospaced
        glyphs_ok = _has_ink(regular, CHECK) and _has_ink(regular, CROSS)
        name = "%s %s (index %d/%d)" % (
            regular.getname()[0], regular.getname()[1], reg_idx, bold_idx)
        return regular, bold, chrome, width, name, glyphs_ok
    sys.exit("No usable monospace font found; edit FONT_CANDIDATES.")


# ==========================================================================
# Demo capture
# ==========================================================================
def capture_demo(repo_root: Path) -> list[str]:
    env = dict(
        os.environ,
        PYTHONIOENCODING="utf-8",
        PYTHONPATH=str(repo_root / "src"),
        NO_COLOR="1",
        TERM="dumb",
        COLUMNS="200",
    )
    venv_py = repo_root / ".venv" / "bin" / "python"
    venv_dg = repo_root / ".venv" / "bin" / "dg"
    candidates = [
        [sys.executable, "-m", "delegation_guard.cli", "demo"],
        [str(venv_py), "-m", "delegation_guard.cli", "demo"],
        [str(venv_dg), "demo"],
        ["dg", "demo"],
    ]
    errors = []
    for cmd in candidates:
        if cmd[0] not in ("dg",) and not Path(cmd[0]).exists():
            continue
        if cmd[0] == "dg" and shutil.which("dg") is None:
            continue
        try:
            proc = subprocess.run(
                cmd, cwd=repo_root, env=env, capture_output=True,
                text=True, encoding="utf-8", timeout=120,
            )
        except OSError as exc:
            errors.append(f"{cmd[:2]}: {exc}")
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            print(f"  demo captured via: {' '.join(cmd)}")
            return proc.stdout.replace("\t", "    ").rstrip("\n").split("\n")
        errors.append(f"{cmd[:2]}: rc={proc.returncode} {proc.stderr.strip()[:160]}")
    sys.exit("Could not run the demo.\n  " + "\n  ".join(errors))


# ==========================================================================
# Layout: wrap, classify, colourise
# ==========================================================================
def wrap_line(line: str, cols: int) -> list[str]:
    if len(line) <= cols:
        return [line]
    stripped = line.lstrip(" ")
    indent = " " * (len(line) - len(stripped))
    # Hang continuations under the text, not under a "[n]" marker.
    hang = indent + ("    " if not indent else "  ")
    body = textwrap.wrap(
        stripped,
        width=max(20, cols - len(hang)),
        break_long_words=True,
        break_on_hyphens=False,
        drop_whitespace=True,
    ) or [""]
    return [(indent if i == 0 else hang) + part for i, part in enumerate(body)]


def classify(line: str) -> str:
    s = line.strip()
    if s.startswith("===="):
        return "dim"
    if STEP_RE.match(line):
        return "step"
    if "delegation-guard demo" in s:
        return "title"
    if f"ALLOWED {CHECK}" in s or s.endswith(CHECK):
        return "ok"
    if f"BLOCKED {CROSS}" in s or "raised AuthorityDenied" in s:
        return "bad"
    if "cascade-revoked" in s:
        return "warn"
    return "text"


def colourise(visual: str, kind: str, first: bool) -> list[tuple[str, str]]:
    """Split one visual (already wrapped) line into (text, style) segments."""
    if not visual.strip():
        return [(visual, "text")]

    if kind == "step" and first:
        m = STEP_RE.match(visual)
        if m:
            return [(m.group(1), "text"), (m.group(2), "step_num"),
                    (m.group(3), "step")]
        return [(visual, "step")]

    if kind == "bad":
        for marker in (f"BLOCKED {CROSS}", "raised AuthorityDenied"):
            idx = visual.find(marker)
            if idx != -1:
                head, tail = visual[: idx + len(marker)], visual[idx + len(marker):]
                return [(head, "bad"), (tail, "bad_body")] if tail else [(head, "bad")]
        return [(visual, "bad_body")]

    if kind == "ok":
        idx = visual.find(f"ALLOWED {CHECK}")
        if idx != -1:
            return [(visual[:idx], "text"), (visual[idx:], "ok")]
        return [(visual, "ok_body")]

    if kind in ("dim", "title", "warn"):
        return [(visual, kind)]
    return [(visual, "text")]


def build_screen_lines(raw: list[str], cols: int):
    """-> list of (segments, duration_ms) for the output phase."""
    logical = [(i, ln) for i, ln in enumerate(raw)]

    def is_break(i: int) -> bool:
        """True if logical line i ends a [n] block (next content starts a new one)."""
        if not raw[i].strip():
            return False
        for j in range(i + 1, len(raw)):
            if not raw[j].strip():
                continue
            return bool(STEP_RE.match(raw[j])) or raw[j].strip().startswith("====")
        return False

    out = []
    for i, line in logical:
        kind = classify(line)
        visuals = wrap_line(line, cols)
        for v_idx, visual in enumerate(visuals):
            segs = colourise(visual, kind, v_idx == 0)
            ms = MS_PER_BLANK if not visual.strip() else MS_PER_LINE
            last_visual = v_idx == len(visuals) - 1
            if last_visual and is_break(i):
                ms += MS_STEP_PAUSE
            out.append((segs, ms))
    return out


# ==========================================================================
# Frame rendering
# ==========================================================================
class Renderer:
    def __init__(self, regular, bold, chrome, char_w):
        self.regular, self.bold, self.chrome = regular, bold, chrome
        self.char_w = char_w
        self._chrome_layer = self._make_chrome()

    def _make_chrome(self) -> Image.Image:
        img = Image.new("RGB", (FRAME_W, FRAME_H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, FRAME_W, TITLE_H - 1], fill=CHROME_BG)
        d.line([(0, TITLE_H - 1), (FRAME_W, TITLE_H - 1)], fill=CHROME_LINE)
        cy = TITLE_H // 2
        for i, colour in enumerate((DOT_RED, DOT_YELLOW, DOT_GREEN)):
            cx = 18 + i * 19
            d.ellipse([cx - 5, cy - 5, cx + 5, cy + 5], fill=colour)
        label = "delegation-guard — demo"
        w = self.chrome.getlength(label)
        d.text(((FRAME_W - w) / 2, cy - CHROME_FONT_SIZE / 2 - 1),
               label, font=self.chrome, fill=CHROME_TEXT)
        return img

    def render(self, screen, cursor_rc=None) -> Image.Image:
        """screen: list of segment-lists (already clipped to ROWS)."""
        img = self._chrome_layer.copy()
        d = ImageDraw.Draw(img)
        for row, segments in enumerate(screen):
            y = TITLE_H + PAD_TOP + row * LINE_H
            col = 0
            for text, style in segments:
                if text:
                    colour, is_bold = STYLES[style]
                    d.text((PAD_X + col * self.char_w, y), text,
                           font=self.bold if is_bold else self.regular, fill=colour)
                    col += len(text)
        if cursor_rc is not None:
            row, col = cursor_rc
            x = PAD_X + col * self.char_w
            y = TITLE_H + PAD_TOP + row * LINE_H
            d.rectangle([x, y + 2, x + self.char_w - 1, y + LINE_H - 4], fill=CURSOR)
        return img


def build_frames(renderer, screen_lines):
    """-> (frames, durations_ms)"""
    frames, durations = [], []
    buf: list[list[tuple[str, str]]] = []

    def visible():
        return buf[-ROWS:]

    def cursor_at(col):
        return (min(len(buf), ROWS) - 1, col)

    # --- phase 1: type the prompt, one character at a time ----------------
    for n in range(len(COMMAND) + 1):
        buf = [[(PROMPT, "prompt"), (COMMAND[:n], "cmd")]]
        frames.append(renderer.render(visible(), cursor_at(len(PROMPT) + n)))
        durations.append(MS_PER_CHAR)
    durations[-1] = MS_AFTER_ENTER  # hold on RETURN

    # --- phase 2: reveal the output, line by line, scrolling as needed ----
    for segments, ms in screen_lines:
        buf.append(segments)
        frames.append(renderer.render(visible()))
        durations.append(ms)

    # --- phase 3: trailing prompt + long hold before the loop -------------
    buf.append([(PROMPT, "prompt")])
    frames.append(renderer.render(visible(), cursor_at(len(PROMPT))))
    durations.append(MS_FINAL_HOLD)
    return frames, durations


# ==========================================================================
# Encoders
# ==========================================================================
def _scaled(frames, scale):
    if scale == 1.0:
        return frames
    w, h = int(frames[0].width * scale) // 2 * 2, int(frames[0].height * scale) // 2 * 2
    return [f.resize((w, h), Image.LANCZOS) for f in frames]


def encode_pillow(frames, durations, out: Path, colors: int, scale: float) -> bool:
    frames = _scaled(frames, scale)
    step = max(1, len(frames) // 10)
    samples = frames[::step] + [frames[-1]]
    strip = Image.new("RGB", (frames[0].width, frames[0].height * len(samples)))
    for i, f in enumerate(samples):
        strip.paste(f, (0, i * frames[0].height))
    palette = strip.quantize(colors=colors, method=Image.Quantize.MEDIANCUT,
                             dither=Image.Dither.NONE)
    pal_frames = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    pal_frames[0].save(
        out, save_all=True, append_images=pal_frames[1:],
        duration=list(durations), loop=0, optimize=True, disposal=1,
    )
    return True


def encode_ffmpeg(frames, durations, out: Path, colors: int, scale: float,
                  workdir: Path) -> bool:
    ffmpeg = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
    if not Path(ffmpeg).exists():
        return False
    frames = _scaled(frames, scale)
    stage = workdir / "ffmpeg_frames"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    for i, f in enumerate(frames):
        f.save(stage / f"f{i:04d}.png")
    listing = ["ffconcat version 1.0"]
    for i, ms in enumerate(durations):
        listing.append(f"file 'f{i:04d}.png'")
        listing.append(f"duration {ms / 1000:.3f}")
    listing.append(f"file 'f{len(frames) - 1:04d}.png'")  # concat demuxer quirk
    concat = stage / "frames.txt"
    concat.write_text("\n".join(listing) + "\n", encoding="utf-8")

    palette = stage / "palette.png"
    base = [ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
            "-f", "concat", "-safe", "0", "-i", str(concat)]
    r1 = subprocess.run(
        base + ["-vf", f"palettegen=max_colors={colors}:stats_mode=full",
                str(palette)], capture_output=True, text=True)
    if r1.returncode != 0:
        print("    ffmpeg palettegen failed:", r1.stderr.strip()[:200])
        return False
    r2 = subprocess.run(
        base + ["-i", str(palette), "-lavfi",
                "paletteuse=dither=none:diff_mode=rectangle",
                "-fps_mode", "vfr", "-loop", "0", str(out)],
        capture_output=True, text=True)
    if r2.returncode != 0:
        print("    ffmpeg paletteuse failed:", r2.stderr.strip()[:200])
        return False
    return True


def encode(frames, durations, out: Path, budget: int, prefer: str, workdir: Path):
    """Try encoder settings until the GIF fits the byte budget."""
    ladder = [
        ("pillow", 128, 1.00),
        ("ffmpeg", 128, 1.00),
        ("pillow", 96, 1.00),
        ("ffmpeg", 96, 1.00),
        ("pillow", 64, 1.00),
        ("ffmpeg", 64, 0.85),
        ("pillow", 64, 0.85),
        ("pillow", 48, 0.75),
    ]
    if prefer in ("pillow", "ffmpeg"):
        ladder = [a for a in ladder if a[0] == prefer]

    best = None  # (size, tmpfile, label)
    tmp = workdir / "candidate.gif"
    for name, colors, scale in ladder:
        fn = encode_pillow if name == "pillow" else encode_ffmpeg
        kwargs = {"workdir": workdir} if name == "ffmpeg" else {}
        if tmp.exists():
            tmp.unlink()
        try:
            ok = fn(frames, durations, tmp, colors, scale, **kwargs)
        except Exception as exc:  # noqa: BLE001 - fall through to next rung
            print(f"    {name}/{colors}c/{scale:.2f}x errored: {exc}")
            continue
        if not ok or not tmp.exists():
            continue
        size = tmp.stat().st_size
        label = f"{name}, {colors} colours, {scale:.2f}x"
        print(f"    {label:<32} -> {size:,} bytes")
        if best is None or size < best[0]:
            keep = workdir / "best.gif"
            shutil.copyfile(tmp, keep)
            best = (size, keep, label)
        if size <= budget:
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tmp, out)
            return size, label
    if best is None:
        sys.exit("Every encoder attempt failed.")
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(best[1], out)
    print(f"  WARNING: smallest result ({best[0]:,} B) still exceeds the "
          f"{budget:,} B budget.")
    return best[0], best[2]


# ==========================================================================
def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default="docs/assets/demo.gif",
                    help="output path, relative to the repo root")
    ap.add_argument("--budget", type=int, default=2_500_000,
                    help="max GIF size in bytes (default 2,500,000)")
    ap.add_argument("--encoder", choices=("auto", "pillow", "ffmpeg"), default="auto")
    ap.add_argument("--workdir", default=None,
                    help="scratch directory for encoder candidates")
    ap.add_argument("--dump-frames", default=None,
                    help="also write first/middle/last frames as PNGs here")
    args = ap.parse_args()

    out = Path(args.out)
    if not out.is_absolute():
        out = repo_root / out
    workdir = Path(args.workdir) if args.workdir else out.parent / ".render-cache"
    workdir.mkdir(parents=True, exist_ok=True)

    print("delegation-guard demo GIF")
    regular, bold, chrome, char_w, font_name, glyphs_ok = pick_font()
    cols = int((FRAME_W - 2 * PAD_X) // char_w)
    print(f"  font: {font_name}  advance={char_w:.3f}px  "
          f"grid={cols}x{ROWS}  frame={FRAME_W}x{FRAME_H}")

    raw = capture_demo(repo_root)
    if not glyphs_ok:
        print("  NOTE: font lacks U+2713/U+2717; substituting [OK]/[X]")
        raw = [ln.replace(CHECK, "[OK]").replace(CROSS, "[X]") for ln in raw]

    screen_lines = build_screen_lines(raw, cols)
    renderer = Renderer(regular, bold, chrome, char_w)
    frames, durations = build_frames(renderer, screen_lines)
    total_s = sum(durations) / 1000
    print(f"  {len(raw)} demo lines -> {len(screen_lines)} wrapped rows, "
          f"{len(frames)} frames, {total_s:.1f}s per loop")

    if args.dump_frames:
        dump = Path(args.dump_frames)
        dump.mkdir(parents=True, exist_ok=True)
        for tag, idx in (("first", 0), ("mid", len(frames) // 2),
                         ("last", len(frames) - 1)):
            frames[idx].save(dump / f"frame-{tag}-{idx:04d}.png")
        print(f"  frames dumped to {dump}")

    print("  encoding:")
    size, label = encode(frames, durations, out, args.budget, args.encoder, workdir)
    shutil.rmtree(workdir, ignore_errors=True)

    with Image.open(out) as gif:
        n_frames = getattr(gif, "n_frames", 1)
        dims = gif.size
    print(f"  wrote {out}")
    print(f"  {size:,} bytes  |  {n_frames} frames  |  {dims[0]}x{dims[1]}  |  {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

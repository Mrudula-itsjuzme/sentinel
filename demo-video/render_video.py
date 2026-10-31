"""Render the Sentinel hackathon demo as a caption-led MP4.

The report values come from the real deterministic incident service. The visual
cards are intentionally restrained so the technical story remains legible.
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import wave

from PIL import Image, ImageDraw, ImageFont, ImageFilter

from sentinel.domain.actions import ActionType
from sentinel.services.incidents import IncidentRunRequest, run_incident


ROOT = Path(__file__).resolve().parent
WIDTH, HEIGHT = 1920, 1080
BG = "#0d1720"
PANEL = "#142532"
TEXT = "#eff6f8"
MUTED = "#9eb2bc"
BLUE = "#5fa9f4"
GREEN = "#56d39c"
AMBER = "#efc15c"
RED = "#ff7f88"


def font(size: int, bold: bool = False):
    path = "/usr/share/fonts/truetype/lato/Lato-Bold.ttf" if bold else "/usr/share/fonts/truetype/lato/Lato-Regular.ttf"
    return ImageFont.truetype(path, size)


def draw_text(draw, xy, text, size=30, fill=TEXT, bold=False, anchor=None):
    draw.text(xy, text, font=font(size, bold), fill=fill, anchor=anchor)


def base(title: str, kicker: str = "SENTINEL · NEBIUS × NVIDIA HACKATHON") -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, WIDTH, 8), fill=BLUE)
    draw_text(draw, (90, 80), kicker, 20, BLUE, True)
    draw_text(draw, (90, 130), title, 62, TEXT, True)
    return image, draw


def footer(draw, label: str):
    draw_text(draw, (90, 1015), label, 20, MUTED)
    draw_text(draw, (1830, 1015), "SENTINEL", 20, MUTED, True, "ra")


def card(draw, box, title, body_lines, accent=BLUE):
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, 18, fill=PANEL, outline="#294353", width=2)
    draw.rectangle((x1, y1, x1 + 7, y2), fill=accent)
    draw_text(draw, (x1 + 32, y1 + 28), title, 28, TEXT, True)
    y = y1 + 84
    for line, color, size in body_lines:
        draw_text(draw, (x1 + 32, y), line, size, color, size >= 27)
        y += size + 18


def screenshot_panel(canvas: Image.Image, path: Path):
    if not path.exists():
        return
    shot = Image.open(path).convert("RGB")
    shot.thumbnail((1510, 690), Image.Resampling.LANCZOS)
    x = (WIDTH - shot.width) // 2
    y = 250
    shadow = Image.new("RGBA", (shot.width + 28, shot.height + 28), (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.rounded_rectangle((12, 12, shot.width + 14, shot.height + 14), 18, fill=(0, 0, 0, 150))
    shadow = shadow.filter(ImageFilter.GaussianBlur(10))
    canvas.paste(shadow, (x - 14, y - 14), shadow)
    canvas.paste(shot, (x, y))
    ImageDraw.Draw(canvas).rounded_rectangle((x, y, x + shot.width, y + shot.height), 16, outline="#496271", width=2)


def screenshot_focus(canvas: Image.Image, path: Path, crop: tuple[int, int, int, int], y: int = 230):
    """Show a real UI crop at readable scale, preserving the source pixels."""
    if not path.exists():
        return
    shot = Image.open(path).convert("RGB").crop(crop)
    scale = min(1740 / shot.width, 760 / shot.height)
    shot = shot.resize((round(shot.width * scale), round(shot.height * scale)), Image.Resampling.LANCZOS)
    x = (WIDTH - shot.width) // 2
    shadow = Image.new("RGBA", (shot.width + 28, shot.height + 28), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((12, 12, shot.width + 14, shot.height + 14), 18, fill=(0, 0, 0, 160))
    canvas.paste(shadow.filter(ImageFilter.GaussianBlur(10)), (x - 14, y - 14), shadow.filter(ImageFilter.GaussianBlur(10)))
    canvas.paste(shot, (x, y))
    ImageDraw.Draw(canvas).rounded_rectangle((x, y, x + shot.width, y + shot.height), 16, outline="#496271", width=2)


def make_slides(report, screenshot: Path, out_dir: Path, rejected_screenshot: Path | None = None, approved_screenshot: Path | None = None):
    out_dir.mkdir(parents=True, exist_ok=True)
    slides = []

    image, draw = base("What if stopping the attack causes more damage?")
    draw_text(draw, (90, 270), "AI proposes an intervention.", 40, TEXT)
    draw_text(draw, (90, 330), "Sentinel simulates the consequences before execution.", 40, MUTED)
    card(draw, (90, 460, 780, 780), "ACTIVE ATTACK PATH", [("alice", TEXT, 30), ("workstation_a  →  internal_host", BLUE, 28), ("→  payroll", RED, 34)])
    card(draw, (850, 460, 1750, 780), "CRITICAL DEPENDENCY", [("Payroll availability", TEXT, 32), ("A safe response must contain the attack", MUTED, 24), ("without breaking the business", AMBER, 28)], AMBER)
    footer(draw, "THE AI PROPOSES · SENTINEL SIMULATES · POLICY DECIDES")
    slides.append((image, 11))

    image, draw = base("1 · Investigate the incident")
    draw_text(draw, (90, 210), "Real Sentinel interface · incident-lateral-001 · SEV-1", 26, MUTED)
    screenshot_panel(image, screenshot)
    footer(draw, "Credential-backed lateral movement · simulation environment · no production changes")
    slides.append((image, 12))

    for label, frame, duration, accent in [
        ("3 · Test the unsafe proposal", rejected_screenshot, 7, RED),
        ("4 · Run the approved response", approved_screenshot, 7, GREEN),
    ]:
        image, draw = base(label)
        draw_text(draw, (90, 220), "Real browser interaction · policy outcome is visible in Sentinel", 28, MUTED)
        if frame and frame.exists():
            screenshot_panel(image, frame)
        draw.rounded_rectangle((90, 900, 1750, 965), 12, fill=PANEL, outline=accent, width=2)
        draw_text(draw, (120, 918), "POLICY REJECTED → SAFE FALLBACK" if accent == RED else "POLICY APPROVED → SIMULATED SUCCESS", 24, accent, True)
        footer(draw, "No production changes · isolated deterministic world clone")
        slides.append((image, duration))

    image, draw = base("2 · Candidate responses in Sentinel")
    draw_text(draw, (90, 220), "Real application state · evidence, proposal, and policy are visible together.", 28, MUTED)
    screenshot_focus(image, approved_screenshot or screenshot, (0, 100, 1067, 620), 250)
    draw.rounded_rectangle((90, 920, 1830, 980), 12, fill=PANEL, outline=GREEN, width=2)
    draw_text(draw, (120, 936), "DISABLE_ACCOUNT · APPROVED IN THE SIMULATED WORLD · PAYROLL AVAILABLE", 23, GREEN, True)
    footer(draw, "Real Sentinel UI · deterministic fallback is explicitly labeled")
    slides.append((image, 17))

    image, draw = base("5 · Policy gate in the real UI")
    draw_text(draw, (90, 220), "Unsafe proposal tested through the actual Sentinel interaction.", 28, MUTED)
    screenshot_focus(image, rejected_screenshot or screenshot, (0, 100, 1067, 620), 250)
    draw.rounded_rectangle((90, 920, 1830, 980), 12, fill=PANEL, outline=RED, width=2)
    draw_text(draw, (120, 936), "ISOLATE_HOST / BLOCK_SMB · REJECTED · USER_IMPACT_EXCEEDED", 23, RED, True)
    footer(draw, "Policy remains deterministic · no production changes")
    slides.append((image, 25))

    image, draw = base("4 · Execute only in the isolated clone")
    draw_text(draw, (90, 220), "The approved intervention never touches production.", 30, MUTED)
    card(draw, (90, 350, 600, 760), "EXECUTION RECEIPT", [("Action", MUTED, 20), ("DISABLE_ACCOUNT", GREEN, 30), ("Mode", MUTED, 20), ("Simulation", TEXT, 28), ("Production changes", MUTED, 20), ("None", GREEN, 28)], GREEN)
    card(draw, (670, 350, 1120, 760), "BEFORE → AFTER", [("Attack paths", MUTED, 20), ("1  →  0", GREEN, 44), ("Payroll", MUTED, 20), ("Available", GREEN, 30)], BLUE)
    card(draw, (1190, 350, 1750, 760), "VERIFICATION", [("Attack graph recomputed", GREEN, 26), ("Critical dependency checked", GREEN, 26), ("Audit record written", GREEN, 26), ("RECOVERED", GREEN, 34)], GREEN)
    footer(draw, "SIMULATED SUCCESS · VERIFIED · AUDITABLE")
    slides.append((image, 18))

    image, draw = base("6 · Verification receipt")
    draw_text(draw, (90, 220), "After approval, Sentinel verifies the simulated outcome and records the audit trail.", 28, MUTED)
    screenshot_focus(image, approved_screenshot or screenshot, (0, 390, 1067, 797), 290)
    draw.rounded_rectangle((90, 920, 1830, 980), 12, fill=PANEL, outline=GREEN, width=2)
    draw_text(draw, (120, 936), "0 REMAINING ATTACK PATHS · PAYROLL AVAILABLE · AUDIT RECORDED", 23, GREEN, True)
    footer(draw, "Simulated execution · independently verified")
    slides.append((image, 18))

    image, draw = base("Sentinel")
    draw_text(draw, (90, 285), "AI-assisted incident response", 46, TEXT, True)
    draw_text(draw, (90, 355), "grounded in simulation and governed by policy.", 46, BLUE)
    draw_text(draw, (90, 540), "The AI proposes.", 34, MUTED)
    draw_text(draw, (90, 600), "Sentinel simulates.", 34, TEXT)
    draw_text(draw, (90, 660), "Policy decides.", 34, GREEN)
    footer(draw, "DEMO SCENARIO: incident-lateral-001 · NO PRODUCTION INTERVENTIONS")
    slides.append((image, 10))

    paths = []
    for index, (slide, _) in enumerate(slides):
        path = out_dir / f"slide-{index:02d}.png"
        slide.save(path)
        paths.append(path)
    return slides, paths


async def get_report():
    return await run_incident(IncidentRunRequest(use_live_reasoning=False))


SUBTITLES = [
    ("00:00:00,000", "00:00:11,000", "What if stopping a cyberattack could cause more damage than the attack itself? Sentinel tests a recommended response before allowing it to proceed."),
    ("00:00:11,000", "00:00:23,000", "This incident is credential-backed lateral movement: Alice's workstation, an internal host, and the payroll dependency are on the active attack path. Four observed signals and two affected identities ground the investigation."),
    ("00:00:23,000", "00:00:40,000", "Sentinel evaluates candidate interventions against the same synthetic world. This run uses the explicit deterministic fallback because no live Nebius credentials are configured. No AI inference is claimed."),
    ("00:00:40,000", "00:01:05,000", "The digital twin predicts that isolating the workstation or blocking SMB would stop the path, but would also make payroll unavailable and impact too many users. The policy controller rejects both. Disabling the compromised account stops the path while preserving payroll, so it is approved."),
    ("00:01:05,000", "00:01:23,000", "The approved action executes only inside an isolated deterministic world clone. Sentinel recomputes the attack graph, confirms zero remaining paths, verifies payroll availability, and records the result."),
    ("00:01:23,000", "00:01:41,000", "Traditional assistants recommend actions. Sentinel predicts consequences first, then lets deterministic policy rules decide. The model may propose; it cannot authorize execution."),
    ("00:01:41,000", "00:02:05,000", "Sentinel: AI-assisted incident response, grounded in simulation and governed by policy. NVIDIA and Nebius integration is available when configured; this recording uses the clearly labeled fallback. Every result is traceable to incident evidence, a simulated outcome, and a policy decision."),
]


def write_subtitles(output: Path):
    lines = []
    for index, (start, end, text) in enumerate(SUBTITLES, 1):
        lines.extend([str(index), f"{start} --> {end}", text, ""])
    output.write_text("\n".join(lines), encoding="utf-8")


def render_mp4(slides, output: Path, temp_dir: Path, voice_provider: str = "auto"):
    duration = sum(duration for _, duration in slides)
    segment_paths = []
    for index, (slide, slide_duration) in enumerate(slides):
        image_path = temp_dir / f"segment-{index:02d}.png"
        slide.save(image_path)
        video_path = temp_dir / f"segment-{index:02d}.mp4"
        subprocess.run(["ffmpeg", "-y", "-loop", "1", "-i", str(image_path), "-t", str(slide_duration), "-r", "30", "-pix_fmt", "yuv420p", "-c:v", "libx264", "-movflags", "+faststart", str(video_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        segment_paths.append(video_path)
    concat = temp_dir / "concat.txt"
    concat.write_text("\n".join(f"file '{path}'" for path in segment_paths), encoding="utf-8")
    silent = temp_dir / "silent.mp4"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat), "-c", "copy", "-movflags", "+faststart", str(silent)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    narration = temp_dir / "narration.wav"
    make_voiceover(narration, temp_dir, voice_provider)
    subtitles = temp_dir / "narration.srt"
    write_subtitles(subtitles)
    subprocess.run(["ffmpeg", "-y", "-i", str(silent), "-i", str(narration), "-i", str(subtitles), "-filter_complex", f"[1:a]apad=pad_dur={duration}[a]", "-map", "0:v", "-map", "[a]", "-map", "2:0", "-t", str(duration), "-c:v", "copy", "-c:a", "aac", "-b:a", "128k", "-c:s", "mov_text", "-metadata:s:s:0", "language=eng", "-metadata:s:s:0", "title=English narration", "-movflags", "+faststart", str(output)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


VOICEOVER = """What if stopping a cyberattack could cause more damage than the attack itself? Sentinel tests a recommended response before allowing it to proceed.

This incident is credential-backed lateral movement: Alice's workstation, an internal host, and the payroll dependency are on the active attack path. Four observed signals and two affected identities ground the investigation.

Sentinel evaluates candidate interventions against the same synthetic world. This run uses the explicit deterministic fallback because no live Nebius credentials are configured. No AI inference is claimed.

The digital twin predicts that isolating the workstation or blocking SMB would stop the path, but would also make payroll unavailable and impact too many users. The policy controller rejects both. Disabling the compromised account stops the path while preserving payroll, so it is approved.

The approved action executes only inside an isolated deterministic world clone. Sentinel recomputes the attack graph, confirms zero remaining paths, verifies payroll availability, and records the result.

Traditional assistants recommend actions. Sentinel predicts consequences first, then lets deterministic policy rules decide. The model may propose; it cannot authorize execution.

Sentinel: AI-assisted incident response, grounded in simulation and governed by policy. NVIDIA and Nebius integration is available when configured; this recording uses the clearly labeled fallback. Every result is traceable to incident evidence, a simulated outcome, and a policy decision."""


def make_voiceover(output: Path, temp_dir: Path, provider: str = "auto"):
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    if provider == "elevenlabs" or (provider == "auto" and api_key):
        if not api_key:
            raise SystemExit("ELEVENLABS_API_KEY is required for --voice-provider elevenlabs")
        voice_id = os.environ.get("ELEVENLABS_VOICE_ID", "21m00Tcm4TlvDq8ikWAM")
        request = urllib.request.Request(
            f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}",
            data=(__import__("json").dumps({
                "text": VOICEOVER,
                "model_id": os.environ.get("ELEVENLABS_MODEL", "eleven_multilingual_v2"),
                "voice_settings": {"stability": 0.48, "similarity_boost": 0.78, "style": 0.18, "use_speaker_boost": True},
            }).encode("utf-8")),
            headers={"xi-api-key": api_key, "Content-Type": "application/json", "Accept": "audio/mpeg"},
            method="POST",
        )
        mp3 = temp_dir / "elevenlabs-narration.mp3"
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                mp3.write_bytes(response.read())
        except Exception as exc:
            raise SystemExit(f"ElevenLabs narration request failed: {exc}") from exc
        subprocess.run(["ffmpeg", "-y", "-i", str(mp3), "-ar", "22050", "-ac", "1", str(output)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    """Use the installed system espeak-ng library without requiring a TTS binary."""
    lib = ctypes.CDLL("libespeak-ng.so.1")
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_short), ctypes.c_int, ctypes.c_void_p)
    chunks: list[bytes] = []

    @callback_type
    def callback(samples, count, _events):
        if samples and count > 0:
            chunks.append(ctypes.string_at(samples, count * 2))
        return 0

    lib.espeak_Initialize.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    lib.espeak_Initialize.restype = ctypes.c_int
    sample_rate = lib.espeak_Initialize(2, 0, None, 0)
    lib.espeak_SetSynthCallback(callback)
    # eSpeak-ng is the only local engine available here. Use its female English
    # variant and conference-friendly pacing; this remains explicitly synthetic.
    lib.espeak_SetVoiceByName.argtypes = [ctypes.c_char_p]
    lib.espeak_SetVoiceByName.restype = ctypes.c_int
    lib.espeak_SetVoiceByName(b"en+f3")
    lib.espeak_SetParameter.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lib.espeak_SetParameter.restype = ctypes.c_int
    lib.espeak_SetParameter(1, 145, 0)  # RATE, words per minute
    lib.espeak_SetParameter(3, 42, 0)   # PITCH, slightly below default
    lib.espeak_SetParameter(4, 35, 0)   # RANGE, restrained variation
    encoded = VOICEOVER.encode("utf-8")
    lib.espeak_Synth.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    lib.espeak_Synth(encoded, len(encoded) + 1, 0, 0, 0, 0, None, None)
    lib.espeak_Synchronize()
    with wave.open(str(output), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(b"".join(chunks))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshot", type=Path, default=ROOT / "assets" / "sentinel-browser.png")
    parser.add_argument("--rejected", type=Path, default=ROOT / "assets" / "sentinel-rejected.png")
    parser.add_argument("--approved", type=Path, default=ROOT / "assets" / "sentinel-approved.png")
    parser.add_argument("--output", type=Path, default=ROOT / "sentinel-devpost-demo.mp4")
    parser.add_argument("--voice-provider", choices=("auto", "elevenlabs", "fallback"), default="auto")
    args = parser.parse_args()
    ROOT.joinpath("assets").mkdir(exist_ok=True)
    if not args.screenshot.exists():
        raise SystemExit(f"Missing application screenshot: {args.screenshot}. Run record_demo.py first.")
    report = asyncio.run(get_report())
    if report.model_call.fallback_used is not True:
        raise SystemExit("Expected the reproducible recording to use the explicit deterministic fallback")
    with tempfile.TemporaryDirectory(prefix="sentinel-video-") as temp:
        slides, _ = make_slides(report, args.screenshot, Path(temp), args.rejected, args.approved)
        render_mp4(slides, args.output, Path(temp), args.voice_provider)
        output = args.output
    print(f"wrote {output} ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

# Sentinel hackathon demo video

This directory contains the reproducible, caption-led Sentinel demo video package.

## Build

From the repository root:

```bash
PYTHONPATH=src /usr/bin/python3 demo-video/render_video.py --output demo-video/sentinel-devpost-demo-final.mp4
ffprobe -v error -show_entries format=duration:format=size:stream=codec_name,codec_type -of default=noprint_wrappers=1 demo-video/sentinel-devpost-demo-final.mp4
```

The renderer runs Sentinel's real deterministic incident loop in-process. It uses the checked-in scenario and does not make a production security change. When no Nebius credentials are configured, the video explicitly says **Deterministic fallback — no AI inference occurred**.

For the natural ElevenLabs narration, set credentials locally and render with the provider explicitly selected (the key is never written to the repository):

```bash
export ELEVENLABS_API_KEY="..."
export ELEVENLABS_VOICE_ID="21m00Tcm4TlvDq8ikWAM"  # configurable; default is a female English voice
PYTHONPATH=src /usr/bin/python3 demo-video/render_video.py --voice-provider elevenlabs --output demo-video/sentinel-devpost-demo-final.mp4
```

An application screenshot is used as visual evidence. Pass a different screenshot with:

```bash
.venv/bin/python demo-video/render_video.py --screenshot /absolute/path/to/sentinel.png
```

## Voice and provenance

The current final MP4 was rendered with ElevenLabs' neural voice using the temporary key supplied for this run; the key is not stored in the repository. It retains the embedded English `mov_text` subtitle track. To reproduce without credentials, use `--voice-provider fallback`; that output is explicitly synthetic. `narration.md` is the exact spoken script and no live-model claim is made in the video.

This environment did not provide a neural TTS engine, licensed neural voice, or configured voice API. The renderer therefore uses an explicitly disclosed synthetic fallback; it does not present that voice as neural or commercial voice talent. For a higher-fidelity release, run the same storyboard with an approved neural TTS provider and replace only the narration input.

The MP4 includes browser frames captured after the real `Run response` and `Test unsafe proposal` interactions, plus report-backed technical cards. A continuous screen recording stream was not available, so the interaction states are presented as close-up evidence cards rather than a fabricated continuous cursor recording.

## Contents

- `sentinel-devpost-demo-final.mp4` — final rendered MP4, 2:05, with AAC narration and embedded subtitles
- `sentinel-devpost-demo.mp4` — original rendered MP4 retained for comparison
- `narration.md` — exact narration script
- `storyboard.md` — shot-by-shot timing and evidence
- `record_demo.py` — captures or copies a browser frame for the renderer
- `render_video.py` — reproducible Pillow + FFmpeg renderer

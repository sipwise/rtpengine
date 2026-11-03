from pathlib import Path
import math
import struct
import subprocess
import json
import collections
import hashlib

p = Path(__file__).resolve().parent
profiles = []
duration = 80
for source in range(2):
    period = (2.0, 2.6)[source]
    first = (0.4, 1.1)[source]
    speech = (0.22, 0.16)[source]
    bursts = [
        {
            "start": first + i * period,
            "end": first + i * period + speech,
            "frequency": (400 if source == 0 else 3400) + i * 50,
        }
        for i in range(int((duration - first - speech) / period) + 1)
    ]
    pcm = bytearray(duration * 16000 * 2)
    for burst in bursts:
        for i in range(
            round(burst["start"] * 16000), round(burst["end"] * 16000)
        ):
            t = i / 16000 - burst["start"]
            envelope = min(1, t / 0.01, (burst["end"] - i / 16000) / 0.01)
            value = round(
                11000
                * max(0, envelope)
                * math.sin(2 * math.pi * burst["frequency"] * i / 16000)
            )
            struct.pack_into("<h", pcm, 2 * i, value)
    raw = p / f"source-{source}.s16"
    raw.write_bytes(pcm)
    awb = p / f"source-{source}.awb"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-y",
            "-f",
            "s16le",
            "-ar",
            "16000",
            "-ac",
            "1",
            "-i",
            str(raw),
            "-c:a",
            "libvo_amrwbenc",
            "-b:a",
            "12650",
            "-dtx",
            "1",
            "-f",
            "amr",
            str(awb),
        ],
        check=True,
    )
    data = awb.read_bytes()
    assert data.startswith(b"#!AMR-WB\n")
    offset = 9
    counts = collections.Counter()
    frames = []
    lengths = [17, 23, 32, 36, 40, 46, 50, 58, 60, 5, 0, 0, 0, 0, 0, 0]
    while offset < len(data):
        toc = data[offset]
        ft = (toc >> 3) & 15
        size = lengths[ft]
        body = data[offset: offset + 1 + size]
        counts[ft] += 1
        if ft != 15:
            frames.append(
                {"frame_index": sum(counts.values()) - 1, "data": body.hex()}
            )
        offset += 1 + size
    profiles.append(
        {
            "source": source,
            "duration": duration,
            "bursts": bursts,
            "packets": frames,
            "frame_types": dict(counts),
        }
    )
    print(
        source,
        "frames",
        sum(counts.values()),
        "types",
        counts,
        "RTP packets",
        len(frames),
        "awb bytes",
        len(data),
    )
for profile in profiles:
    source = profile["source"]
    name = f"source-{source}.awb"
    del profile["packets"]
    profile.update(
        {
            "file": name,
            "sha256": hashlib.sha256((p / name).read_bytes()).hexdigest(),
            "jitter_amplitude": 0.015 + source * 0.005,
            "jitter_step": 0.37 - source * 0.11,
        }
    )
    (p / f"source-{source}.s16").unlink()
(p / "profiles.json").write_text(json.dumps(profiles, indent=2) + "\n")

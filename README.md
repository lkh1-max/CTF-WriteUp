# CTF Forensics Write‑up — Recovering what was last on screen (DWM dump)

**Challenge**: *Recover what was last on the screen.*  
A scientist is connected over RDP to a Windows machine. A strange window flashes and then the session locks, but the EDR captured a **`dwm.exe.dmp`** file. Question: **What was on the screen at that moment?**

---

## Idea & technical background

- **dwm.exe (Desktop Window Manager)** is the Windows compositor: it holds the windows' **GPU surfaces** and composes them into the displayed frame.
- These surfaces are **not** compressed image files (PNG/JPEG) that can be carved directly. They are **raw buffers** in **8‑bit BGRA** format (4 bytes per pixel).
- Each row usually has a **pitch/stride** **≥ `width*4`** because of **padding/alignment** (often aligned to 256 B). If the image is rebuilt **without respecting the pitch**, you get stripes, skew or a torn image.

**Goal**: find the exact *offset* of the surface in the dump, determine **`width × height`**, **`pitch`** and the **channel order** (BGRA), then rebuild it as a PNG.

---

## Solving process (summary)

1. **Coarse sweep**: jump through the dump in large steps, quickly trying a few common resolutions and both BGRA/RGBA to *"sniff"* for image fragments.
2. **Anchor**: a single **torn image** is enough to prove a surface exists and to infer the **resolution** and the **approximate offset region**.
3. **Focused reconstruction**: a script reads **`pitch*height`** bytes, copies **only the first `width*4`** bytes of each row (dropping padding), converts **BGRA→RGBA** (alpha=255) and saves a PNG.
4. **Fine sweep around the anchor**: shift the offset by **±512 KiB** in **4 KiB** steps, try a few **pitch** values (e.g. `W*4 ± 256`) → export PNGs in bulk → **filter out junk** → **browse** until a complete image appears.
5. **Result**: the (ransom) dialog becomes clearly visible → read the **flag**.

---

## Step 1 — Coarse sweep to find a "fingerprint"

The Python script below scans the file in **16 MiB steps**, trying common resolutions and both **BGRA/RGBA** channel orders. Conversion uses **ImageMagick** (`convert`).

```python
#!/usr/bin/env python3
# initial_sweep.py — coarse "slicing" of raw data to look for screenshot traces

import os, subprocess
src = "dwm.exe.dmp"
outdir = "raw_candidates"
os.makedirs(outdir, exist_ok=True)

# try a few common desktop resolutions
sizes = [(1366,768),(1024,768),(1920,1080),(1600,900)]
step = 16 * 1024 * 1024  # 16 MiB step
L = os.path.getsize(src)
idx = 0

def try_slice(offset, w, h, fmt, idx):
    size = w * h * 4
    with open(src, "rb") as f:
        f.seek(offset)
        buf = f.read(size)
    if len(buf) != size:
        return False
    raw = f"{outdir}/slice_{idx:05d}_{w}x{h}_{fmt}_off{offset}.raw"
    png = raw.replace(".raw", ".png")
    open(raw, "wb").write(buf)
    try:
        subprocess.run(["convert", "-size", f"{w}x{h}", "-depth", "8", f"{fmt}:{raw}", png],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.remove(raw)
        print("made", png)
        return True
    except Exception:
        try: os.remove(raw)
        except: pass
        return False

for offset in range(0, L, step):
    for (w,h) in sizes:
        for fmt in ("bgra","rgba"):
            try_slice(offset, w, h, fmt, idx)
            idx += 1

print("initial sweep done; check raw_candidates/")
```

> **Expectation**: most outputs are junk, but **one torn image** (dialog border, menu bar, etc.) is enough to **prove a surface exists** and **hint at W×H and the offset region**.

---

## Step 2 — Focused reconstruction (repack the surface)

From the torn image, the resolution is **1024×768**. With `W=1024`, `W*4 = 4096` B, but because rows are aligned to 256 B we try **3840, 4096, 4352**.

The script below reads **`pitch*H`** bytes from `offset`, **takes only the first `W*4`** bytes of each row, converts **BGRA→RGBA**, forces **alpha=255** and writes a PNG.

```python
#!/usr/bin/env python3
# repack_surface.py — read pitch*height at offset, copy width*4 per row,
# BGRA -> RGBA, alpha = 255, save PNG.

import sys
from PIL import Image

def repack_and_save(src, offset, W, H, pitch, out):
    need = pitch * H
    with open(src, "rb") as f:
        f.seek(offset)
        buf = f.read(need)
    if len(buf) != need:
        print("FAIL: short read")
        return False

    rowbytes = W * 4
    tight = bytearray(W * H * 4)
    for y in range(H):
        row = buf[y * pitch : y * pitch + rowbytes]
        if len(row) < rowbytes:
            print("FAIL: short row")
            return False
        # BGRA -> RGBA, alpha = 255
        for x in range(0, rowbytes, 4):
            b = row[x+0]
            g = row[x+1]
            r = row[x+2]
            idx = (y * rowbytes) + x
            tight[idx + 0] = r
            tight[idx + 1] = g
            tight[idx + 2] = b
            tight[idx + 3] = 255

    Image.frombytes("RGBA", (W, H), bytes(tight)).save(out, optimize=True)
    return True

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("usage: repack_surface.py dump offset width height pitch out.png")
        sys.exit(1)
    src = sys.argv[1]
    offset = int(sys.argv[2])      # decimal number, not 0x...
    W = int(sys.argv[3])
    H = int(sys.argv[4])
    pitch = int(sys.argv[5])
    out = sys.argv[6]
    ok = repack_and_save(src, offset, W, H, pitch, out)
    print("OK" if ok else "FAIL")
```

**Install dependencies**:
```bash
python3 -m pip install pillow
# and ImageMagick if you use the coarse sweep script:
# sudo apt install imagemagick
```

---

## Step 3 — Fine sweep around the anchor offset

Shift the offset by **±512 KiB** in **4 KiB** steps and try the 3 `pitch` values above; rebuild images in bulk, delete images that are too small (< 20 KB) to cut down junk, then list the **20 largest images** (usually the "right" ones) to inspect.

```bash
BASE=16777216         # anchor offset from the coarse sweep
SPAN=524288           # ±512 KiB
STEP=4096             # 4 KiB step
W=1024; H=768
PITCHES=(3840 4096 4352)

mkdir -p png_1024x768_scan
for off in $(seq $((BASE - SPAN)) $STEP $((BASE + SPAN))); do
  for p in "${PITCHES[@]}"; do
    out=png_1024x768_scan/cand_off${off}_p${p}.png
    python3 repack_surface.py dwm.exe.dmp $off $W $H $p $out >/dev/null 2>&1 || true
    # drop junk PNGs that are too small
    [ -f "$out" ] && [ $(stat -c%s "$out") -lt 20000 ] && rm -f "$out"
  done
done

# show the 20 largest files to review first
ls -S png_1024x768_scan/*.png | head -20
```

> **Tip**: if the colours look off (blue/red swapped), the channel order may be wrong. DWM is usually **BGRA**, so the repack step already converts to RGBA.

---

## Result

Browsing the rebuilt images, the stripes/tearing disappear as `pitch` and `offset` become correct. The ransom dialog is clearly visible in this example file:

```
png_1024x768_scan/cand_off17158144_p4096.png
```

**Flag**:  
```
sun{r3m0t3_pwn4g3_QQ}
```

---

## Pitfalls & practical notes

- **Wrong pitch** → striped, skewed or torn image. Pin down the pitch before blaming the channel order.
- **Wrong channel order** → strange colours. DWM is usually **BGRA**.
- **Wrong W×H** → distorted image with unrecognisable UI. Try several common desktop resolutions.
- **Non-contiguous offset** (rare) → needs another approach (Volatility plugins, extracting surface handles, etc.). In this challenge the buffer is raw and contiguous, so the method above is the best fit.

---

## One-shot summary

```bash
# 1) Coarse sweep to "sniff" the offset & W×H (optional, needs ImageMagick)
python3 initial_sweep.py

# 2) Once 1024x768 is suspected and an anchor offset is known (e.g. BASE=16777216),
# fine-sweep around the anchor and rebuild PNGs in bulk:
BASE=16777216; SPAN=524288; STEP=4096; W=1024; H=768
PITCHES=(3840 4096 4352)
mkdir -p png_1024x768_scan
for off in $(seq $((BASE - SPAN)) $STEP $((BASE + SPAN))); do
  for p in "${PITCHES[@]}"; do
    python3 repack_surface.py dwm.exe.dmp $off $W $H $p png_1024x768_scan/cand_off${off}_p${p}.png       >/dev/null 2>&1 || true
  done
done
ls -S png_1024x768_scan/*.png | head -20
```

---

### Conclusion

- With a **DWM** dump, "*last on screen*" is most likely a **screenshot** sitting in a **BGRA surface** with a **pitch**.  
- Fast workflow: **coarse sweep → anchor → pitch-aware repack → fine sweep → inspect results**.  
- Applied to this challenge, we recover the **ransom dialog** and read the **flag**: `sun{r3m0t3_pwn4g3_QQ}`.

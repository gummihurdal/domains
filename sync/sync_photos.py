#!/usr/bin/env python3
"""Sync photos from a public pCloud folder into photos/ with a manifest.
The folder's public link code lives in photos/source.txt (just the code, or full link).
Filenames become captions: 'Lake Bled — the proposal.jpg' -> 'Lake Bled — the proposal'.
"""
import json, os, re, io, sys, zipfile, urllib.request, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHOTOS = os.path.join(ROOT, "photos")
MANIFEST = os.path.join(PHOTOS, "manifest.json")
SOURCE = os.path.join(PHOTOS, "source.txt")
MAX_W = 1800
QUALITY = 72

def get_code():
    if not os.path.exists(SOURCE):
        return None
    raw = open(SOURCE).read().strip()
    if not raw:
        return None
    m = re.search(r"code=([A-Za-z0-9]+)", raw)
    return m.group(1) if m else raw

def api(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)

def main():
    code = get_code()
    if not code:
        print("photos/source.txt empty — nothing to sync")
        return
    meta = api(f"https://eapi.pcloud.com/showpublink?code={code}")
    if meta.get("result") != 0:
        sys.exit(f"pCloud error: {meta}")
    md = meta["metadata"]
    files = md.get("contents", []) if md.get("isfolder") else [md]
    images = [f for f in files if not f.get("isfolder") and f.get("category") == 1]
    print(f"{len(images)} images in pCloud folder")

    os.makedirs(PHOTOS, exist_ok=True)
    manifest = []
    if os.path.exists(MANIFEST):
        manifest = json.load(open(MANIFEST))
    have = {m["source_id"]: m for m in manifest if "source_id" in m}

    from PIL import Image, ImageOps

    changed = False
    keep_ids = set()
    for f in sorted(images, key=lambda x: x.get("created", "")):
        fid = str(f["fileid"])
        keep_ids.add(fid)
        stamp = f"{fid}:{f.get('hash','')}"
        if fid in have and have[fid].get("stamp") == stamp:
            continue
        # download via zip endpoint (single-file zip; avoids IP-bound direct links)
        print("downloading", f["name"])
        url = f"https://eapi.pcloud.com/getpubzip?code={code}&fileids={fid}"
        with urllib.request.urlopen(url, timeout=300) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
        data = z.read(z.namelist()[0])
        im = Image.open(io.BytesIO(data))
        im = ImageOps.exif_transpose(im).convert("RGB")
        if im.width > MAX_W:
            im = im.resize((MAX_W, round(im.height * MAX_W / im.width)), Image.LANCZOS)
        slug = re.sub(r"[^a-z0-9]+", "-", os.path.splitext(f["name"])[0].lower()).strip("-")[:60] or fid
        fname = f"{slug}-{fid[-5:]}.jpg"
        im.save(os.path.join(PHOTOS, fname), quality=QUALITY, optimize=True, progressive=True)
        caption = os.path.splitext(f["name"])[0].strip()
        entry = {"source_id": fid, "stamp": stamp, "file": fname,
                 "caption": caption, "w": im.width, "h": im.height,
                 "created": f.get("created", "")}
        have[fid] = entry
        changed = True

    # drop entries removed from the folder (keep non-pCloud entries like lugano)
    new_manifest = [m for m in manifest if "source_id" not in m]
    removed = [m for m in manifest if "source_id" in m and m["source_id"] not in keep_ids]
    for m in removed:
        p = os.path.join(PHOTOS, m["file"])
        if os.path.exists(p):
            os.remove(p)
        changed = True
    new_manifest += sorted([m for m in have.values() if m["source_id"] in keep_ids],
                           key=lambda m: m.get("created", ""))
    if changed or new_manifest != manifest:
        json.dump(new_manifest, open(MANIFEST, "w"), indent=1, ensure_ascii=False)
        print(f"manifest updated: {len(new_manifest)} photos")
    else:
        print("no changes")

if __name__ == "__main__":
    main()

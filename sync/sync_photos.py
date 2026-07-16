#!/usr/bin/env python3
"""Sync photos from a public pCloud folder into photos/ — encrypted.
- Folder link code in photos/source.txt
- Password from env PHOTOS_PASSWORD (GitHub Actions secret)
- Each image: compressed, then AES-256-GCM encrypted -> photos/<name>.enc
- photos/manifest.json: {salt, check, photos:[...]}
Filenames become captions.
"""
import json, os, re, io, sys, zipfile, base64, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHOTOS = os.path.join(ROOT, "photos")
MANIFEST = os.path.join(PHOTOS, "manifest.json")
SOURCE = os.path.join(PHOTOS, "source.txt")
MAX_W, QUALITY = 1600, 70
PBKDF2_ITERS = 250_000

def b64(b): return base64.b64encode(b).decode()
def unb64(s): return base64.b64decode(s)

def get_code():
    if not os.path.exists(SOURCE): return None
    raw = open(SOURCE).read().strip()
    if not raw: return None
    m = re.search(r"code=([A-Za-z0-9]+)", raw)
    return m.group(1) if m else raw

def api(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)

def main():
    code = get_code()
    if not code:
        print("photos/source.txt empty — nothing to sync"); return
    password = os.environ.get("PHOTOS_PASSWORD", "")
    if not password:
        sys.exit("PHOTOS_PASSWORD secret not set")

    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    os.makedirs(PHOTOS, exist_ok=True)
    old = {}
    salt = os.urandom(16)
    if os.path.exists(MANIFEST):
        m = json.load(open(MANIFEST))
        if isinstance(m, dict):
            old = {p["source_id"]: p for p in m.get("photos", []) if "source_id" in p}
            if m.get("salt"): salt = unb64(m["salt"])

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    key = kdf.derive(password.encode())
    aes = AESGCM(key)

    def encrypt(data: bytes) -> bytes:
        iv = os.urandom(12)
        return iv + aes.encrypt(iv, data, None)

    meta = api(f"https://eapi.pcloud.com/showpublink?code={code}")
    if meta.get("result") != 0: sys.exit(f"pCloud error: {meta}")
    md = meta["metadata"]
    files = md.get("contents", []) if md.get("isfolder") else [md]
    images = [f for f in files if not f.get("isfolder") and f.get("category") == 1
              and "(2)" not in f["name"]]
    print(f"{len(images)} images in folder")

    from PIL import Image, ImageOps
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except ImportError:
        pass

    import datetime
    def caption_for(name):
        base = os.path.splitext(name)[0].strip()
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ _]", base)
        if m:
            try:
                d = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                return d.strftime("%-d %B %Y")
            except ValueError:
                pass
        return base

    photos, keep = [], set()
    for f in sorted(images, key=lambda x: x.get("created", "")):
        fid = str(f["fileid"]); keep.add(fid)
        stamp = f"{fid}:{f.get('hash','')}"
        if fid in old and old[fid].get("stamp") == stamp and os.path.exists(os.path.join(PHOTOS, old[fid]["file"])):
            photos.append(old[fid]); continue
        print("processing", f["name"])
        url = f"https://eapi.pcloud.com/getpubzip?code={code}&fileids={fid}"
        with urllib.request.urlopen(url, timeout=300) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
        im = Image.open(io.BytesIO(z.read(z.namelist()[0])))
        im = ImageOps.exif_transpose(im).convert("RGB")
        if im.width > MAX_W:
            im = im.resize((MAX_W, round(im.height * MAX_W / im.width)), Image.LANCZOS)
        buf = io.BytesIO(); im.save(buf, "JPEG", quality=QUALITY, optimize=True, progressive=True)
        slug = re.sub(r"[^a-z0-9]+", "-", os.path.splitext(f["name"])[0].lower()).strip("-")[:60] or fid
        fname = f"{slug}-{fid[-5:]}.enc"
        open(os.path.join(PHOTOS, fname), "wb").write(encrypt(buf.getvalue()))
        photos.append({"source_id": fid, "stamp": stamp, "file": fname,
                       "caption": caption_for(f["name"]),
                       "w": im.width, "h": im.height, "created": f.get("created","")})

    # remove deleted
    for fid, p in old.items():
        if fid not in keep:
            fp = os.path.join(PHOTOS, p["file"])
            if os.path.exists(fp): os.remove(fp)

    out = {"v": 2, "salt": b64(salt), "iters": PBKDF2_ITERS,
           "check": b64(encrypt(b"grace-ok")),
           "photos": sorted(photos, key=lambda p: p.get("created",""))}
    json.dump(out, open(MANIFEST, "w"), indent=1, ensure_ascii=False)
    print(f"manifest: {len(photos)} encrypted photos")

if __name__ == "__main__":
    main()

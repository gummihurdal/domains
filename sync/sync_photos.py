#!/usr/bin/env python3
"""Sync photos from a public pCloud folder into photos/ — encrypted.
- Folder link code in photos/source.txt
- Password from env PHOTOS_PASSWORD (GitHub Actions secret)
- Each image: compressed, then AES-256-GCM encrypted -> photos/<name>.enc
- photos/manifest.json: {salt, check, photos:[...]}
Filenames become captions.
- Uploads from the site: env PHOTOS_UPLOAD_CODE (GitHub Actions secret) is the code of a pCloud *upload link* into the
  same folder. It is stored in the manifest encrypted with the photo key ("upload"), so only someone who unlocked the
  gallery can upload. The page names uploaded files "YYYY-MM-DD HH-MM-SS <original>"; that date becomes the
  photo's date in the timeline (new files only — entries already in the manifest keep their dates).
- Each entry also gets "added" (pCloud upload time); the page lists uploads since its ADDED_FROM date last, in upload order.
- Edits from the page (Supabase table photo_edits: delete / restore / purge / rotate / caption / fav / unfav) are signed
  with an HMAC key derived from the password; only rows that verify count. Applied here: "deleted" marks an entry for the
  Trash, after PURGE_DAYS (or "purge") its files are removed and it is tombstoned in "removed" so the pCloud original never
  comes back; "rotate" re-encodes the photo turned; "caption" and "fav" are stored on the entry.
"""
import json, os, re, io, sys, time, hmac, hashlib, zipfile, base64, urllib.request
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHOTOS = os.path.join(ROOT, "photos")
MANIFEST = os.path.join(PHOTOS, "manifest.json")
SOURCE = os.path.join(PHOTOS, "source.txt")
MAX_W, QUALITY = 1600, 70
PBKDF2_ITERS = 250_000
PURGE_DAYS = 30
EDITS_URL = "https://mjphpctvuxmbjhmcscoj.supabase.co/rest/v1/photo_edits?select=photo_id,action,value,ts,sig&order=ts.asc&limit=100000"
# public anon key (the same one the page ships); the table is append-only and every row must carry a valid signature
ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1qcGhwY3R2dXhtYmpobWNzY29q"
            "Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzIyMjgzMzQsImV4cCI6MjA4NzgwNDMzNH0.dsmzK7SS4_RSC5wbN6ifhjRlOSbfDZjIcfh2MKkDQIs")


def fold_edits(rows):
    """Signed edit log (oldest first) -> {photo_id: state}. Same rules as the page's fold()."""
    out = {}
    for e in sorted(rows, key=lambda e: (int(e["ts"]), e["sig"])):
        s = out.setdefault(e["photo_id"], {"deleted": None, "purged": False, "rot": 0, "caption": None, "fav": None})
        a = e["action"]
        if s["purged"]:
            continue
        if a == "delete": s["deleted"] = int(e["ts"])
        elif a == "restore": s["deleted"] = None
        elif a == "purge" and s["deleted"]: s["purged"] = True
        elif a == "rotate":
            try: s["rot"] = (s["rot"] + int(e["value"])) % 360
            except ValueError: pass
        elif a == "caption": s["caption"] = e["value"][:300]
        elif a == "fav": s["fav"] = True
        elif a == "unfav": s["fav"] = False
    return out


def load_edits(password, salt):
    """Verified edit state, or None when the log cannot be read (then nothing about edits changes this run)."""
    try:
        req = urllib.request.Request(EDITS_URL, headers={"apikey": ANON_KEY, "Authorization": "Bearer " + ANON_KEY})
        with urllib.request.urlopen(req, timeout=30) as r:
            rows = json.load(r)
    except Exception as e:
        print("photo edits unavailable, left as they were:", e); return None
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt + b"edits", iterations=PBKDF2_ITERS).derive(password.encode())
    good = []
    for e in rows:
        msg = f"{e['photo_id']}\n{e['action']}\n{e['value']}\n{e['ts']}".encode()
        if hmac.compare_digest(hmac.new(k, msg, hashlib.sha256).hexdigest(), str(e.get("sig", ""))):
            good.append(e)
    print(f"photo edits: {len(good)} verified of {len(rows)}")
    return fold_edits(good)

def b64(b): return base64.b64encode(b).decode()
def when(x):
    """pCloud/manifest RFC-2822 date -> sortable; missing or odd -> epoch."""
    try: return parsedate_to_datetime(x.get("created", "")).timestamp()
    except Exception: return 0.0
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
    old = {}; old_m = {}
    salt = os.urandom(16)
    if os.path.exists(MANIFEST):
        m = json.load(open(MANIFEST))
        if isinstance(m, dict):
            old_m = m
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
    def walk(items, depth=0):
        for f in items:
            if f.get("isfolder"):
                if depth < 3:          # pCloud upload links create "Files from <name> on <date>/" per upload
                    yield from walk(f.get("contents", []), depth + 1)
            else:
                yield f
    files = list(walk(md.get("contents", []))) if md.get("isfolder") else [md]
    names = {f["name"] for f in files if not f.get("isfolder")}
    def is_redundant_dupe(f):
        # "IMG (2).jpg" is redundant only while "IMG.jpg" still exists
        if "(2)" not in f["name"]:
            return False
        original = re.sub(r"\s*\(2\)", "", f["name"], count=1)
        return original in names

    removed = list(old_m.get("removed", []))          # tombstones of photos deleted for good
    gone_ids = {x.get("id") for x in removed} | {x.get("fid") for x in removed}
    gone_hash = {x.get("hash") for x in removed if x.get("hash")}
    usable, seen_hash = [], {}
    for f in sorted(files, key=when):
        if f.get("isfolder") or is_redundant_dupe(f):
            continue
        if str(f["fileid"]) in gone_ids or (f.get("hash") and str(f["hash"]) in gone_hash):
            continue
        h = str(f.get("hash") or "")
        if h and h in seen_hash:
            print("same content as", seen_hash[h]["name"], "- skipping", f["name"]); continue
        if h: seen_hash[h] = f
        usable.append(f)
    images = [f for f in usable if f.get("category") == 1]
    videos = [f for f in usable if f.get("category") == 2
              and f.get("size", 0) <= 300 * 1024 * 1024]
    big_videos = [f for f in usable if f.get("category") == 2
                  and f.get("size", 0) > 300 * 1024 * 1024]   # streamed from pCloud
    print(f"{len(images)} images, {len(videos)} transcodable videos, {len(big_videos)} streamed videos")

    from PIL import Image, ImageOps
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except ImportError:
        pass

    import datetime
    def created_for(f, im=None):
        """When the picture was taken: EXIF DateTimeOriginal, else a 'YYYY-MM-DD HH-MM-SS' name prefix (site uploads,
        phone exports), else pCloud's created time (= when it was put in the folder)."""
        if im is not None:
            try:
                ex = im.getexif()
                raw = ex.get_ifd(0x8769).get(36867) or ex.get(306)      # DateTimeOriginal, else DateTime
                if raw:
                    d = datetime.datetime.strptime(str(raw)[:19], "%Y:%m:%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
                    return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
            except Exception:
                pass
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ _](\d{2})-(\d{2})-(\d{2})", f["name"])
        if m:
            try:
                d = datetime.datetime(*(int(x) for x in m.groups()), tzinfo=datetime.timezone.utc)
                return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
            except ValueError:
                pass
        return f.get("created", "")

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

    # index old entries by content hash for rename/dedupe carry-over
    old_by_hash = {}
    for e in old.values():
        h = (e.get("stamp") or "").split(":")[-1]
        if h: old_by_hash.setdefault(h, e)

    photos, keep = [], set()
    for f in sorted(images, key=when):
        fid = str(f["fileid"]); keep.add(fid)
        fhash = str(f.get('hash',''))
        stamp = f"{fid}:{fhash}"
        if fid in old and old[fid].get("stamp") == stamp and os.path.exists(os.path.join(PHOTOS, old[fid]["file"])):
            photos.append(old[fid]); continue
        carried = old_by_hash.get(fhash)
        if carried and os.path.exists(os.path.join(PHOTOS, carried["file"])):
            # same content under a new fileid (deleted original, "(2)" copy remains)
            keep.add(carried["source_id"])
            e = dict(carried); e["stamp"] = stamp; e["fid"] = fid
            photos.append(e)
            print("carried over (same content):", f["name"])
            continue
        print("processing", f["name"])
        url = f"https://eapi.pcloud.com/getpubzip?code={code}&fileids={fid}"
        try:
            with urllib.request.urlopen(url, timeout=300) as r:
                z = zipfile.ZipFile(io.BytesIO(r.read()))
            raw = Image.open(io.BytesIO(z.read(z.namelist()[0])))
            raw.load()
        except Exception as e:
            print("  cannot read, skipping:", type(e).__name__, e); keep.discard(fid); continue
        im = ImageOps.exif_transpose(raw).convert("RGB")
        if im.width > MAX_W:
            im = im.resize((MAX_W, round(im.height * MAX_W / im.width)), Image.LANCZOS)
        buf = io.BytesIO(); im.save(buf, "JPEG", quality=QUALITY, optimize=True, progressive=True)
        slug = re.sub(r"[^a-z0-9]+", "-", os.path.splitext(f["name"])[0].lower()).strip("-")[:60] or fid
        fname = f"{slug}-{fid[-5:]}.enc"
        open(os.path.join(PHOTOS, fname), "wb").write(encrypt(buf.getvalue()))
        photos.append({"source_id": fid, "stamp": stamp, "file": fname,
                       "caption": caption_for(f["name"]),
                       "w": im.width, "h": im.height, "created": created_for(f, raw)})

    # ---- videos: transcode to 720p mp4, poster frame, encrypt both ----
    import subprocess, tempfile
    for f in sorted(videos, key=when):
        fid = str(f["fileid"]); keep.add(fid)
        stamp = f"{fid}:{f.get('hash','')}"
        if fid in old and old[fid].get("stamp") == stamp and os.path.exists(os.path.join(PHOTOS, old[fid]["file"])):
            photos.append(old[fid]); continue
        print("video:", f["name"], f.get("size",0)//(1024*1024), "MB")
        url = f"https://eapi.pcloud.com/getpubzip?code={code}&fileids={fid}"
        with tempfile.TemporaryDirectory() as td:
            zp = os.path.join(td, "v.zip")
            with urllib.request.urlopen(url, timeout=1800) as r, open(zp, "wb") as out:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk: break
                    out.write(chunk)
            with zipfile.ZipFile(zp) as z:
                src = os.path.join(td, "src")
                open(src, "wb").write(z.read(z.namelist()[0]))
            mp4 = os.path.join(td, "out.mp4")
            poster = os.path.join(td, "poster.jpg")
            try:
                subprocess.run(["ffmpeg", "-y", "-i", src,
                                "-vf", "scale='min(1280,iw)':-2",
                                "-c:v", "libx264", "-crf", "28", "-preset", "veryfast",
                                "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart",
                                mp4], check=True, capture_output=True)
                subprocess.run(["ffmpeg", "-y", "-ss", "0.5", "-i", mp4,
                                "-frames:v", "1", "-vf", "scale='min(1200,iw)':-2",
                                "-q:v", "4", poster], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print("  ffmpeg failed, skipping:", e.stderr[-200:] if e.stderr else "")
                keep.discard(fid); continue
            if os.path.getsize(mp4) > 95 * 1024 * 1024:
                print("  transcoded output still too large, skipping")
                keep.discard(fid); continue
            # probe dimensions
            probe = subprocess.run(["ffprobe", "-v", "quiet", "-select_streams", "v:0",
                                    "-show_entries", "stream=width,height", "-of", "csv=p=0", mp4],
                                   capture_output=True, text=True).stdout.strip().split(",")
            vw, vh = (int(probe[0]), int(probe[1])) if len(probe) == 2 else (0, 0)
            slug = re.sub(r"[^a-z0-9]+", "-", os.path.splitext(f["name"])[0].lower()).strip("-")[:60] or fid
            vname = f"{slug}-{fid[-5:]}.mp4.enc"
            pname = f"{slug}-{fid[-5:]}.poster.enc"
            open(os.path.join(PHOTOS, vname), "wb").write(encrypt(open(mp4, "rb").read()))
            open(os.path.join(PHOTOS, pname), "wb").write(encrypt(open(poster, "rb").read()))
            photos.append({"source_id": fid, "stamp": stamp, "type": "video",
                           "file": vname, "poster": pname,
                           "caption": caption_for(f["name"]),
                           "w": vw, "h": vh, "mb": round(os.path.getsize(mp4)/1048576, 1),
                           "created": created_for(f)})

    # ---- oversized videos: encrypted thumbnail poster, streamed from pCloud on tap ----
    for f in sorted(big_videos, key=when):
        fid = str(f["fileid"]); keep.add(fid)
        stamp = f"{fid}:{f.get('hash','')}"
        if fid in old and old[fid].get("stamp") == stamp and os.path.exists(os.path.join(PHOTOS, old[fid].get("poster",""))):
            photos.append(old[fid]); continue
        print("stream poster:", f["name"], f.get("size",0)//(1024*1024), "MB")
        turl = f"https://eapi.pcloud.com/getpubthumb?code={code}&fileid={fid}&size=1200x900&type=jpg&crop=0"
        try:
            with urllib.request.urlopen(turl, timeout=120) as r:
                thumb = r.read()
        except Exception as e:
            print("  no thumb, skipping:", e); keep.discard(fid); continue
        slug = re.sub(r"[^a-z0-9]+", "-", os.path.splitext(f["name"])[0].lower()).strip("-")[:60] or fid
        pname = f"{slug}-{fid[-5:]}.poster.enc"
        open(os.path.join(PHOTOS, pname), "wb").write(encrypt(thumb))
        photos.append({"source_id": fid, "stamp": stamp, "type": "stream",
                       "fileid": int(fid), "poster": pname,
                       "caption": caption_for(f["name"]),
                       "mb": round(f.get("size",0)/1048576),
                       "created": created_for(f)})

    # remove deleted
    for fid, p in old.items():
        if fid not in keep:
            for k in ("file", "poster"):
                if p.get(k):
                    fp = os.path.join(PHOTOS, p[k])
                    if os.path.exists(fp): os.remove(fp)

    def stable(old_b64, plain):
        """Re-use the previous ciphertext if it still decrypts to `plain` (random IVs would otherwise change the
        manifest every hour and trigger a commit + deploy for nothing)."""
        try:
            raw = unb64(old_b64 or "")
            if aes.decrypt(raw[:12], raw[12:], None) == plain: return old_b64
        except Exception:
            pass
        return b64(encrypt(plain))

    # "added" = when the file reached pCloud (upload time). The page shows everything added since ADDED_FROM at the
    # end of the gallery, in upload order, so new uploads always come last. First seen value is kept.
    uploaded = {str(f["fileid"]): f.get("created", "") for f in files}
    for p in photos:
        if not p.get("added"):
            a = uploaded.get(str(p.get("fid") or p.get("source_id")))
            if a: p["added"] = a

    # ---- edits from the page: trash, purge, rotate, caption, favourite ----
    ed = load_edits(password, salt)
    if ed is not None:
        now_ms = int(time.time() * 1000)
        kept = []
        for p in photos:
            st = ed.get(p["source_id"]) or ed.get(p.get("fid", ""))
            if not st:
                p.pop("deleted", None); p.pop("fav", None); kept.append(p); continue
            if st["purged"] or (st["deleted"] and now_ms - st["deleted"] > PURGE_DAYS * 86400_000):
                for k in ("file", "poster"):
                    if p.get(k) and os.path.exists(os.path.join(PHOTOS, p[k])): os.remove(os.path.join(PHOTOS, p[k]))
                removed.append({"id": p["source_id"], "fid": p.get("fid") or p["source_id"],
                                "hash": (p.get("stamp") or "").split(":")[-1], "t": now_ms})
                print("removed for good:", p.get("file") or p.get("poster")); continue
            if st["deleted"]: p["deleted"] = st["deleted"]
            else: p.pop("deleted", None)
            if st["caption"] is not None: p["caption"] = st["caption"]
            if st["fav"]: p["fav"] = True
            else: p.pop("fav", None)
            want, have = st["rot"] % 360, int(p.get("rot", 0)) % 360
            if not p.get("type") and want != have:
                try:
                    src = os.path.join(PHOTOS, p["file"]); raw = open(src, "rb").read()
                    im = Image.open(io.BytesIO(aes.decrypt(raw[:12], raw[12:], None)))
                    im = im.rotate(-((want - have) % 360), expand=True)          # PIL turns counter-clockwise
                    buf = io.BytesIO(); im.convert("RGB").save(buf, "JPEG", quality=90, optimize=True, progressive=True)
                    base = re.sub(r"-r\d+\.enc$", ".enc", p["file"])
                    new = base if want == 0 else base[:-4] + f"-r{want}.enc"
                    open(os.path.join(PHOTOS, new), "wb").write(encrypt(buf.getvalue()))
                    if new != p["file"]: os.remove(src)
                    p["file"], p["w"], p["h"] = new, im.width, im.height
                    if want: p["rot"] = want
                    else: p.pop("rot", None)
                    print("rotated", new, want)
                except Exception as e:
                    print("  rotate failed:", p.get("file"), e)
            kept.append(p)
        photos = kept

    out = {"v": 2, "salt": b64(salt), "iters": PBKDF2_ITERS, "pcloud": code,
           "check": stable(old_m.get("check"), b"grace-ok"),
           "photos": sorted(photos, key=when), "removed": removed}
    upload_code = os.environ.get("PHOTOS_UPLOAD_CODE", "").strip()
    if upload_code:
        m = re.search(r"code=([A-Za-z0-9]+)", upload_code)
        out["upload"] = stable(old_m.get("upload"), (m.group(1) if m else upload_code).encode())
    else:
        print("PHOTOS_UPLOAD_CODE not set - the site shows no upload box")
    json.dump(out, open(MANIFEST, "w"), indent=1, ensure_ascii=False)
    print(f"manifest: {len(photos)} encrypted photos")

if __name__ == "__main__":
    main()

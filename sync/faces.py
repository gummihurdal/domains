"""People for the gallery: find faces and group the same person, on the CPU, with no outside service.

OpenCV's YuNet face detector + SFace face embeddings (both free models from github.com/opencv/opencv_zoo, downloaded
once per run into FACE_MODELS, default /tmp/face-models). Called by sync_photos.py with decrypted photo bytes; the
results (boxes + 128-number embeddings) are stored encrypted, never in the clear.
"""
import io, os, tempfile, urllib.request

import numpy as np

MODELS = {
    "det": ("face_detection_yunet_2023mar.onnx",
            "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"),
    "rec": ("face_recognition_sface_2021dec.onnx",
            "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"),
}
CACHE = os.environ.get("FACE_MODELS", os.path.join(tempfile.gettempdir(), "face-models"))
MIN_SCORE = 0.88        # detector confidence
MIN_SIDE = 40           # px on the 1600 px photo: smaller faces are too blurry to tell apart
SAME_PERSON = 0.40      # cosine similarity to a group's average face (SFace's own same-person line is 0.363)

_det = _rec = None


def _path(kind):
    name, url = MODELS[kind]
    os.makedirs(CACHE, exist_ok=True)
    p = os.path.join(CACHE, name)
    if not os.path.exists(p) or os.path.getsize(p) < 100_000:
        with urllib.request.urlopen(url, timeout=120) as r, open(p + ".part", "wb") as out:
            out.write(r.read())
        os.replace(p + ".part", p)
    return p


def _models():
    global _det, _rec
    if _det is None:
        import cv2
        _det = cv2.FaceDetectorYN.create(_path("det"), "", (320, 320), MIN_SCORE, 0.3, 5000)
        _rec = cv2.FaceRecognizerSF.create(_path("rec"), "")
    return _det, _rec


def _decode(data: bytes):
    import cv2
    return cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)


def detect(data: bytes):
    """JPEG bytes -> [{"box": [x, y, w, h], "score": s, "emb": [128 floats, unit length]}], biggest faces first."""
    im = _decode(data)
    if im is None:
        return []
    det, rec = _models()
    h, w = im.shape[:2]
    det.setInputSize((w, h))
    _, found = det.detect(im)
    out = []
    for f in (found if found is not None else []):
        x, y, fw, fh, score = float(f[0]), float(f[1]), float(f[2]), float(f[3]), float(f[-1])
        if score < MIN_SCORE or min(fw, fh) < MIN_SIDE:
            continue
        emb = rec.feature(rec.alignCrop(im, f)).flatten().astype(np.float64)
        n = np.linalg.norm(emb)
        if not n:
            continue
        out.append({"box": [int(x), int(y), int(fw), int(fh)], "score": round(score, 3),
                    "emb": [round(float(v), 5) for v in emb / n]})
    out.sort(key=lambda d: -d["box"][2] * d["box"][3])
    return out


def crop(data: bytes, box, size=160) -> bytes:
    """A square portrait around one face, as a small JPEG."""
    from PIL import Image
    im = Image.open(io.BytesIO(data)).convert("RGB")
    x, y, w, h = box
    cx, cy, side = x + w / 2, y + h / 2, max(w, h) * 1.7
    l, t = max(0, cx - side / 2), max(0, cy - side / 2)
    r, b = min(im.width, l + side), min(im.height, t + side)
    im = im.crop((int(l), int(t), int(r), int(b))).resize((size, size), Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=82)
    return buf.getvalue()


def group(items):
    """items: [(face_key, emb list, score)] -> list of groups (lists of face keys), biggest group first.
    Greedy and deterministic: the clearest faces start groups; each face joins the group whose average face is most
    similar, if similar enough."""
    groups = []                                  # [keys, sum vector]
    for key, emb, _ in sorted(items, key=lambda t: (-t[2], t[0])):
        v = np.asarray(emb, dtype=np.float64)
        best, best_s = None, SAME_PERSON
        for g in groups:
            c = g[1] / np.linalg.norm(g[1])
            s = float(c @ v)
            if s >= best_s:
                best, best_s = g, s
        if best is None:
            groups.append([[key], v.copy()])
        else:
            best[0].append(key)
            best[1] += v
    out = [sorted(g[0]) for g in groups]
    out.sort(key=lambda ks: (-len(ks), ks[0]))
    return out

import os
import re
import json
import base64
import hashlib

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF87a": "GIF87a Image",
    b"GIF89a": "GIF89a Image",
    b"%PDF-": "PDF Document",
    b"PK\x03\x04": "ZIP / DOCX / XLSX / APK Archive",
    b"Rar!\x1a\x07": "RAR Archive",
    b"\x7fELF": "Linux ELF Binary",
    b"MZ": "Windows PE Executable (EXE/DLL)",
    b"ID3": "MP3 Audio (ID3v2)",
    b"OggS": "OGG Media",
    b"SQLite format 3\x00": "SQLite 3 Database",
}


def inspect_file_deep(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        return {"error": "File not found"}

    with open(filepath, "rb") as f:
        data = f.read()

    detected_type = "Unknown / Plain Text"
    for sig, label in MAGIC_SIGNATURES.items():
        if data.startswith(sig):
            detected_type = label
            break

    raw_strings = re.findall(rb"[\x20-\x7e]{6,}", data)
    decoded_strings = [s.decode("ascii", errors="ignore") for s in raw_strings[:40]]
    full_text = "\n".join(s.decode("ascii", errors="ignore") for s in raw_strings)
    embedded_urls = sorted(set(re.findall(r"https?://[^\s\"'<>]+", full_text)))[:25]
    embedded_emails = sorted(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", full_text)))[:25]

    result = {
        "file_path": os.path.abspath(filepath),
        "size_bytes": len(data),
        "detected_magic_type": detected_type,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "embedded_urls": embedded_urls,
        "embedded_emails": embedded_emails,
        "sample_strings": decoded_strings[:20],
        "exif": {},
    }

    try:
        from PIL import Image, ExifTags
        img = Image.open(filepath)
        result["image_dimensions"] = f"{img.width}x{img.height} ({img.format})"
        exif = img.getexif()
        if exif:
            result["exif"] = {str(ExifTags.TAGS.get(k, k)): str(v) for k, v in exif.items()}
    except Exception:
        pass

    return result


def decode_jwt_unverified(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {"error": "Invalid JWT format (expected header.payload.signature)"}

    def b64url_decode(seg):
        rem = len(seg) % 4
        if rem:
            seg += "=" * (4 - rem)
        return json.loads(base64.urlsafe_b64decode(seg.encode("utf-8")).decode("utf-8"))

    try:
        return {
            "header": b64url_decode(parts[0]),
            "payload": b64url_decode(parts[1]),
            "has_signature": len(parts) == 3 and bool(parts[2]),
        }
    except Exception as e:
        return {"error": f"JWT decode failed: {e}"}

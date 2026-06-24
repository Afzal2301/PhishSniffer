import hashlib
import base64
import asyncio
from io import BytesIO


def _compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


def _detect_file_type(data: bytes) -> str:
    signatures = {
        b"%PDF": "pdf",
        b"PK\x03\x04": "zip_or_office",
        b"\xd0\xcf\x11\xe0": "legacy_office",
        b"MZ": "executable",
        b"\x7fELF": "elf_binary",
    }
    for sig, ftype in signatures.items():
        if data[:len(sig)] == sig:
            return ftype
    return "unknown"


def _check_pdf(data: bytes) -> dict:
    text = data.decode("latin-1", errors="ignore")
    findings = []

    if "/JavaScript" in text or "/JS " in text:
        findings.append("JavaScript embedded in PDF")
    if "/OpenAction" in text:
        findings.append("OpenAction trigger found")
    if "/Launch" in text:
        findings.append("Launch action found")
    if "/EmbeddedFile" in text:
        findings.append("Embedded file object found")
    if "/AA " in text:
        findings.append("Additional actions found")

    return {"suspicious": bool(findings), "findings": findings}


def _check_office(data: bytes) -> dict:
    findings = []
    try:
        from olefile import OleFileIO
        ole = OleFileIO(BytesIO(data))
        streams = ole.listdir()
        for stream in streams:
            name = "/".join(stream).lower()
            if "vba" in name or "macro" in name:
                findings.append(f"VBA stream found: {name}")
        ole.close()
    except Exception:
        pass

    return {"suspicious": bool(findings), "findings": findings}


async def analyze(filename: str, file_content_b64: str) -> dict:
    loop = asyncio.get_event_loop()

    try:
        data = base64.b64decode(file_content_b64)
    except Exception:
        return {"error": "Invalid base64 content"}

    hashes = _compute_hashes(data)
    file_type = _detect_file_type(data)
    size_bytes = len(data)

    findings = {}
    if file_type == "pdf":
        findings = await loop.run_in_executor(None, _check_pdf, data)
    elif file_type in ("zip_or_office", "legacy_office"):
        findings = await loop.run_in_executor(None, _check_office, data)
    elif file_type == "executable":
        findings = {"suspicious": True, "findings": ["Executable file — high risk"]}

    return {
        "filename": filename,
        "file_type": file_type,
        "size_bytes": size_bytes,
        "hashes": hashes,
        "analysis": findings
    }
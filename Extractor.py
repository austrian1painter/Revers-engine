"""
APKVoid — APK extractor, manifest parser, DEX/string scanner.
Works with androguard (preferred) and falls back to raw zip parsing.
"""

import io
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Data structures ───────────────────────────────────────────────

@dataclass
class ManifestInfo:
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list[str] = field(default_factory=list)
    activities: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    receivers: list[dict] = field(default_factory=list)
    providers: list[dict] = field(default_factory=list)
    exported_count: int = 0
    uses_cleartext_traffic: bool = False
    debuggable: bool = False


@dataclass
class CertInfo:
    sha256: str = ""
    sha1: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    is_self_signed: bool = False
    expired: bool = False


@dataclass
class StringHit:
    value: str
    category: str
    description: str
    score: int
    source_file: str = ""


@dataclass
class CodeHit:
    pattern: str
    category: str
    severity: str
    score: int
    description: str
    source_file: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class APKReport:
    apk_path: str = ""
    apk_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    cert: CertInfo = field(default_factory=CertInfo)
    code_hits: list[CodeHit] = field(default_factory=list)
    string_hits: list[StringHit] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    risk_score: int = 0
    verdict: str = "UNKNOWN"
    errors: list[str] = field(default_factory=list)


# ── Hash helpers ──────────────────────────────────────────────────

def _hash_file(path: str) -> tuple[str, str, str]:
    import hashlib
    md5  = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


# ── Certificate parsing ───────────────────────────────────────────

def _parse_cert(apk_zip: zipfile.ZipFile) -> CertInfo:
    info = CertInfo()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        import datetime

        cert_paths = [n for n in apk_zip.namelist()
                      if re.match(r"META-INF/.*\.(RSA|DSA|EC)", n, re.I)]
        if not cert_paths:
            return info

        raw = apk_zip.read(cert_paths[0])

        # PKCS#7 SignedData — extract the embedded X.509 cert
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            certs = pkcs7.load_der_pkcs7_certificates(raw)
            if not certs:
                return info
            cert = certs[0]
        except Exception:
            # Try raw DER as fallback
            cert = x509.load_der_x509_certificate(raw)

        fp_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        fp_sha1   = cert.fingerprint(hashes.SHA1()).hex()
        info.sha256 = ":".join(fp_sha256[i:i+2].upper() for i in range(0, len(fp_sha256), 2))
        info.sha1   = ":".join(fp_sha1[i:i+2].upper() for i in range(0, len(fp_sha1), 2))

        info.subject = cert.subject.rfc4514_string()
        info.issuer  = cert.issuer.rfc4514_string()
        info.not_before = str(cert.not_valid_before_utc)
        info.not_after  = str(cert.not_valid_after_utc)
        info.is_self_signed = (cert.subject == cert.issuer)
        info.expired = cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc)

    except ImportError:
        info.sha256 = "(install 'cryptography' for cert analysis)"
    except Exception as e:
        info.sha256 = f"(parse error: {e})"
    return info


# ── Manifest parsing ──────────────────────────────────────────────

def _parse_manifest_androguard(apk_obj) -> ManifestInfo:
    """Parse manifest using androguard APK object."""
    m = ManifestInfo()
    m.package      = apk_obj.get_package() or ""
    m.version_name = apk_obj.get_androidversion_name() or ""
    m.version_code = str(apk_obj.get_androidversion_code() or "")
    m.min_sdk      = str(apk_obj.get_min_sdk_version() or "")
    m.target_sdk   = str(apk_obj.get_target_sdk_version() or "")
    m.permissions  = list(apk_obj.get_permissions())

    def _component_dict(name: str, comp_type: str) -> dict:
        exported = apk_obj.get_attribute_value(comp_type, "exported", name) or ""
        return {"name": name, "exported": exported.lower() in ("true", "1")}

    for a in apk_obj.get_activities():
        d = _component_dict(a, "activity")
        m.activities.append(d)
        if d["exported"]: m.exported_count += 1

    for s in apk_obj.get_services():
        d = _component_dict(s, "service")
        m.services.append(d)
        if d["exported"]: m.exported_count += 1

    for r in apk_obj.get_receivers():
        d = _component_dict(r, "receiver")
        m.receivers.append(d)
        if d["exported"]: m.exported_count += 1

    for p in apk_obj.get_providers():
        m.providers.append({"name": p})

    # Security flags from manifest XML
    try:
        xml_str = apk_obj.get_android_manifest_axml().get_xml().decode("utf-8", errors="ignore")
        m.debuggable = 'android:debuggable="true"' in xml_str
        m.uses_cleartext_traffic = 'android:usesCleartextTraffic="true"' in xml_str
    except Exception:
        pass

    return m


def _parse_manifest_raw(apk_zip: zipfile.ZipFile) -> ManifestInfo:
    """Minimal manifest parser when androguard is unavailable.
    Reads permissions from binary AndroidManifest.xml using a simple heuristic.
    """
    m = ManifestInfo()
    m.package = "(androguard not installed — limited parsing)"
    try:
        raw = apk_zip.read("AndroidManifest.xml")
        # Extract readable strings from binary AXML
        text = raw.decode("utf-8", errors="ignore")
        # Grab anything that looks like a permission
        found = re.findall(r"android\.permission\.\w+", text)
        m.permissions = list(set(found))
    except Exception as e:
        m.permissions = []
    return m


# ── String scanning ───────────────────────────────────────────────

def _scan_strings(content: str, source_file: str) -> list[StringHit]:
    from apkvoid.patterns import STRING_PATTERNS
    hits: list[StringHit] = []
    for pattern, category, description, score in STRING_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches[:5]:  # cap to 5 per pattern per file
            hits.append(StringHit(
                value=match[:120],
                category=category,
                description=description,
                score=score,
                source_file=source_file,
            ))
    return hits


# ── DEX / Smali code scanning ─────────────────────────────────────

def _scan_dex_androguard(dex_obj, source_file: str) -> tuple[list[CodeHit], list[StringHit]]:
    from apkvoid.patterns import DEX_PATTERNS
    code_hits: list[CodeHit] = []
    string_hits: list[StringHit] = []

    # Collect all class descriptors + method names for pattern matching
    api_corpus = set()
    string_corpus: list[str] = []

    for cls in dex_obj.get_classes():
        api_corpus.add(cls.get_name())
        for method in cls.get_methods():
            api_corpus.add(method.get_name())
            if method.get_code():
                for ins in method.get_code().get_bc().get_instructions():
                    if hasattr(ins, "get_string"):
                        s = ins.get_string()
                        if s:
                            string_corpus.append(s)

    # Match API patterns
    matched_patterns: set[str] = set()
    for p in DEX_PATTERNS:
        if p.pattern in matched_patterns:
            continue
        for entry in api_corpus:
            if p.pattern in entry:
                code_hits.append(CodeHit(
                    pattern=p.pattern,
                    category=p.category,
                    severity=p.severity,
                    score=p.score,
                    description=p.description,
                    source_file=source_file,
                    tags=p.tags,
                ))
                matched_patterns.add(p.pattern)
                break

    # Scan strings from DEX
    combined = "\n".join(string_corpus)
    string_hits.extend(_scan_strings(combined, source_file))

    return code_hits, string_hits


# ── Main analysis entry point ─────────────────────────────────────

def analyze_apk(apk_path: str) -> APKReport:
    report = APKReport(apk_path=apk_path)

    path = Path(apk_path)
    if not path.exists():
        report.errors.append(f"File not found: {apk_path}")
        report.verdict = "ERROR"
        return report

    report.apk_size = path.stat().st_size
    report.md5, report.sha1, report.sha256 = _hash_file(apk_path)

    # ── Open ZIP ──
    try:
        apk_zip = zipfile.ZipFile(apk_path, "r")
    except zipfile.BadZipFile as e:
        report.errors.append(f"Not a valid ZIP/APK: {e}")
        report.verdict = "ERROR"
        return report

    # ── Certificate ──
    report.cert = _parse_cert(apk_zip)

    # ── File inventory ──
    names = apk_zip.namelist()
    report.dex_files    = [n for n in names if n.endswith(".dex")]
    report.native_libs  = [n for n in names if n.endswith(".so")]
    report.assets       = [n for n in names if n.startswith("assets/")]

    # ── Manifest + DEX via androguard ──
    try:
        from androguard.misc import AnalyzeAPK
        apk_obj, dex_list, analysis = AnalyzeAPK(apk_path)
        report.manifest = _parse_manifest_androguard(apk_obj)

        for i, dex in enumerate(dex_list):
            fname = f"classes{'2' if i > 0 else ''}.dex"
            chits, shits = _scan_dex_androguard(dex, fname)
            report.code_hits.extend(chits)
            report.string_hits.extend(shits)

    except ImportError:
        report.errors.append(
            "androguard not installed — DEX analysis skipped. "
            "Run: pip install androguard"
        )
        report.manifest = _parse_manifest_raw(apk_zip)
        # Fall back to raw string scan of APK bytes
        raw = path.read_bytes().decode("latin-1")
        report.string_hits = _scan_strings(raw, path.name)

    except Exception as e:
        report.errors.append(f"androguard error: {e}")
        report.manifest = _parse_manifest_raw(apk_zip)

    apk_zip.close()

    # ── Scan assets/res for embedded scripts ──
    try:
        with zipfile.ZipFile(apk_path) as z:
            for name in z.namelist():
                if any(name.endswith(ext) for ext in
                       (".js", ".php", ".sh", ".py", ".lua", ".html")):
                    try:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        hits = _scan_strings(content, name)
                        report.string_hits.extend(hits)
                    except Exception:
                        pass
    except Exception:
        pass

    # ── Deduplicate string hits ──
    seen = set()
    dedup: list[StringHit] = []
    for h in report.string_hits:
        key = (h.value[:40], h.category)
        if key not in seen:
            seen.add(key)
            dedup.append(h)
    report.string_hits = dedup

    # ── Scoring ──
    from apkvoid.permissions import score_permissions, RISK_SCORES
    perm_score, _ = score_permissions(report.manifest.permissions)

    code_score   = sum(h.score for h in report.code_hits)
    string_score = sum(h.score for h in report.string_hits)

    # Bonus penalties
    bonus = 0
    if report.cert.is_self_signed:
        bonus += 20
    if report.cert.expired:
        bonus += 30
    if report.manifest.debuggable:
        bonus += 40
    if report.manifest.uses_cleartext_traffic:
        bonus += 20
    if len(report.native_libs) > 0:
        bonus += 15
    if report.manifest.exported_count > 5:
        bonus += 25

    report.risk_score = perm_score + code_score + string_score + bonus

    # ── Verdict ──
    if report.risk_score >= 400:
        report.verdict = "LIKELY_MALWARE"
    elif report.risk_score >= 200:
        report.verdict = "SUSPICIOUS"
    elif report.risk_score >= 80:
        report.verdict = "POTENTIALLY_UNWANTED"
    else:
        report.verdict = "CLEAN"

    return report

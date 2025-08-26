#!/usr/bin/env python3
"""
CTI IOC Parser — Çok formatlı siber tehdit istihbaratı ayrıştırıcı

Neler desteklenir (yalnızca standart kütüphane ile):
- STIX 2.1 JSON (bundle -> objects)
- MISP JSON (Event/Attribute)
- OpenIOC XML (sınırlı)
- CSV (başlıkta value/type veya ioc/value sütunları)
- Düz metin IOC listesi (satır başına bir IOC)

Çıktılar:
- JSON Lines (varsayılan)
- CSV
- STIX 2.1 Bundle (normalize edilmiş IOCs -> indicator objects)

Kullanım örnekleri:
  python cti_parser.py feed.json -o out.jsonl
  python cti_parser.py feed.csv --out-format csv -o out.csv
  python cti_parser.py feed.txt --source "OSINT Feed X" --tlp AMBER
  python cti_parser.py feed.json --out-format stix -o indicators.json

Notlar:
- Harici bağımlılık yoktur. Standart kütüphane ile çalışır.
- Tarih alanları esnek parse edilir (ISO8601/DNS/HTTP tarihleri vs. en yaygın biçimler).
- IOC tipleri: ip, ipv6, domain, url, md5, sha1, sha256, email, filename, mutex (bazı formatlarda çıkabilir)
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple
from xml.etree import ElementTree as ET

# ----------------------- Yardımcılar -----------------------

ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%m-%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%a, %d %b %Y %H:%M:%S %Z",
]

def parse_datetime(val: Optional[str]) -> Optional[str]:
    if not val or not isinstance(val, str):
        return None
    v = val.strip()
    if not v:
        return None
    if v.endswith("Z") and "+" not in v:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
    for f in ISO_FORMATS:
        try:
            dt = datetime.strptime(v, f)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            continue
    m = re.search(r"(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2}))?", v)
    if m:
        base = m.group(1)
        clock = m.group(2) or "00:00:00"
        try:
            dt = datetime.fromisoformat(f"{base}T{clock}+00:00")
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return None
    return None

RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_URL = re.compile(r"\b(?:https?|ftp)://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.I)
RE_DOMAIN = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)


def detect_ioc_type(value: str) -> Optional[str]:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ipv6" if ":" in v else "ip"
    except ValueError:
        pass
    if RE_MD5.fullmatch(v):
        return "md5"
    if RE_SHA1.fullmatch(v):
        return "sha1"
    if RE_SHA256.fullmatch(v):
        return "sha256"
    if RE_EMAIL.fullmatch(v):
        return "email"
    if RE_URL.fullmatch(v):
        return "url"
    if RE_DOMAIN.fullmatch(v):
        return "domain"
    return None

# ----------------------- Veri model -----------------------

@dataclass
class IOC:
    value: str
    type: str
    source: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: Optional[int] = None
    tlp: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None

# ----------------------- Format tespit -----------------------

def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".csv"}:
        return "csv"
    if suffix in {".xml"}:
        return "openioc"
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, dict):
            if data.get("type") == "bundle" and isinstance(data.get("objects"), list):
                return "stix"
            if "Event" in data or "Attribute" in data:
                return "misp"
        if isinstance(data, list):
            return "jsonlist"
    except Exception:
        pass
    return "text"

# ----------------------- Ayrıştırıcılar -----------------------

class BaseParser:
    def __init__(self, path: Path, default_source: Optional[str]=None, tlp: Optional[str]=None):
        self.path = path
        self.default_source = default_source
        self.tlp = normalize_tlp(tlp)

    def parse(self) -> Iterator[IOC]:
        raise NotImplementedError

class TextParser(BaseParser):
    def parse(self) -> Iterator[IOC]:
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                v = line.strip()
                if not v or v.startswith("#"):
                    continue
                t = detect_ioc_type(v)
                if not t:
                    continue
                yield IOC(value=v, type=t, source=self.default_source, tlp=self.tlp)

class CSVParser(BaseParser):
    def parse(self) -> Iterator[IOC]:
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            cols = {c.lower(): c for c in reader.fieldnames or []}
            def pick(*names: str) -> Optional[str]:
                for n in names:
                    if n in cols:
                        return cols[n]
                return None
            col_val = pick("value", "ioc", "indicator", "artifact", "indicator_value")
            col_type = pick("type", "ioc_type", "indicator_type")
            col_first = pick("first_seen", "firstseen", "first_seen_at", "first_seen_date")
            col_last = pick("last_seen", "lastseen", "last_seen_at", "last_seen_date")
            col_conf = pick("confidence")
            col_src = pick("source", "feed", "provider")
            col_tlp = pick("tlp")
            col_tags = pick("tags", "label", "labels")
            col_desc = pick("description", "comment")

            for row in reader:
                raw = dict(row)
                value = (row.get(col_val) or "").strip() if col_val else ""
                if not value:
                    continue
                t = str(row.get(col_type) or "").strip().lower() if col_type else None
                if not t:
                    t = detect_ioc_type(value) or "unknown"
                fs = parse_datetime(row.get(col_first)) if col_first else None
                ls = parse_datetime(row.get(col_last)) if col_last else None
                conf = try_int(row.get(col_conf)) if col_conf else None
                src = row.get(col_src) or self.default_source
                tlp = normalize_tlp(row.get(col_tlp) or self.tlp)
                tags = split_tags(row.get(col_tags)) if col_tags else []
                desc = row.get(col_desc)
                yield IOC(value=value, type=t, source=src, first_seen=fs, last_seen=ls,
                          confidence=conf, tlp=tlp, tags=tags, description=desc, raw=raw)

class JSONListParser(BaseParser):
    def parse(self) -> Iterator[IOC]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return
        for item in data:
            if isinstance(item, dict):
                value = str(item.get("value") or item.get("ioc") or item.get("indicator") or "").strip()
                if not value:
                    continue
                t = str(item.get("type") or "").lower() or detect_ioc_type(value) or "unknown"
                fs = parse_datetime(item.get("first_seen"))
                ls = parse_datetime(item.get("last_seen"))
                conf = try_int(item.get("confidence"))
                src = item.get("source") or self.default_source
                tlp = normalize_tlp(item.get("tlp") or self.tlp)
                tags = split_tags(item.get("tags"))
                desc = item.get("description")
                yield IOC(value=value, type=t, source=src, first_seen=fs, last_seen=ls,
                          confidence=conf, tlp=tlp, tags=tags, description=desc, raw=item)
            elif isinstance(item, str):
                t = detect_ioc_type(item)
                if t:
                    yield IOC(value=item, type=t, source=self.default_source, tlp=self.tlp)

class STIXParser(BaseParser):
    def parse(self) -> Iterator[IOC]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        bundle_objs = data.get("objects", []) if isinstance(data, dict) else []
        for obj in bundle_objs:
            if not isinstance(obj, dict):
                continue
            t = obj.get("type")
            if t == "indicator":
                pattern = obj.get("pattern", "")
                ts = obj.get("created") or obj.get("valid_from")
                fs = parse_datetime(ts)
                ls = parse_datetime(obj.get("modified"))
                conf = try_int(obj.get("confidence"))
                tlp = extract_tlp(obj)
                src = self.default_source or first_label(obj) or obj.get("created_by_ref")
                tags = labels_to_tags(obj)
                for val, ioc_type in extract_from_stix_pattern(pattern):
                    yield IOC(value=val, type=ioc_type, source=src, first_seen=fs, last_seen=ls,
                              confidence=conf, tlp=tlp or self.tlp, tags=tags, description=obj.get("description"), raw=obj)
            elif t in {"domain-name", "file", "url", "ipv4-addr", "ipv6-addr", "email-addr"}:
                for val, ioc_type in extract_from_stix_sco(obj):
                    yield IOC(value=val, type=ioc_type, source=self.default_source, tlp=self.tlp, raw=obj)

class MISPParser(BaseParser):
    def parse(self) -> Iterator[IOC]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        events = []
        if isinstance(data, dict):
            if "Event" in data:
                events = [data["Event"]]
            elif isinstance(data.get("response"), list):
                for e in data["response"]:
                    if "Event" in e:
                        events.append(e["Event"])
            elif isinstance(data.get("Event"), list):
                events = data["Event"]
        for ev in events:
            src = self.default_source or ev.get("info") or ev.get("Orgc", {}).get("name")
            tlp = normalize_tlp(ev.get("Tag", [{}])[0].get("name") if ev.get("Tag") else None) or self.tlp
            attributes = ev.get("Attribute", [])
            for a in attributes:
                value = (a.get("value") or "").strip()
                if not value:
                    continue
                ioc_type = misp_type_to_ioc(a.get("type") or "") or detect_ioc_type(value) or "unknown"
                fs = parse_datetime(a.get("first_seen") or a.get("timestamp"))
                ls = parse_datetime(a.get("last_seen"))
                conf = try_int(a.get("confidence"))
                tags = [t.get("name") for t in (a.get("Tag") or []) if isinstance(t, dict)]
                desc = a.get("comment")
                yield IOC(value=value, type=ioc_type, source=src, first_seen=fs, last_seen=ls,
                          confidence=conf, tlp=tlp, tags=tags, description=desc, raw=a)

class OpenIOCParser(BaseParser):
    def parse(self) -> Iterator[IOC]:
        tree = ET.parse(self.path)
        root = tree.getroot()
        for inditem in root.iter():
            if inditem.tag.endswith("IndicatorItem"):
                search = ""
                val = ""
                for ctx in inditem:
                    if ctx.tag.endswith("Context"):
                        search = (ctx.attrib.get("search", "") or "").lower()
                    if ctx.tag.endswith("Content"):
                        val = (ctx.text or "").strip()
                ioc_type = openioc_search_to_type(search) or detect_ioc_type(val) or "unknown"
                if val:
                    yield IOC(value=val, type=ioc_type, source=self.default_source, tlp=self.tlp)

# ----------------------- STIX yardımcıları -----------------------

STIX_PATTERN_EXTRACTORS = [
    (re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]", re.I), "domain"),
    (re.compile(r"\[url:value\s*=\s*'([^']+)'\]", re.I), "url"),
    (re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", re.I), "ip"),
    (re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", re.I), "ipv6"),
    (re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]", re.I), "email"),
    (re.compile(r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]", re.I), "md5"),
    (re.compile(r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]", re.I), "sha1"),
    (re.compile(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", re.I), "sha256"),
]

def extract_from_stix_pattern(pattern: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for rx, t in STIX_PATTERN_EXTRACTORS:
        for m in rx.finditer(pattern or ""):
            out.append((m.group(1), t))
    return out

def extract_from_stix_sco(obj: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    t = obj.get("type")
    if t == "domain-name" and obj.get("value"):
        out.append((obj["value"], "domain"))
    elif t == "url" and obj.get("value"):
        out.append((obj["value"], "url"))
    elif t == "ipv4-addr" and obj.get("value"):
        out.append((obj["value"], "ip"))
    elif t == "ipv6-addr" and obj.get("value"):
        out.append((obj["value"], "ipv6"))
    elif t == "email-addr" and obj.get("value"):
        out.append((obj["value"], "email"))
    elif t == "file":
        hashes = obj.get("hashes") or {}
        for k, v in hashes.items():
            k_up = (k or "").upper()
            if k_up == "MD5":
                out.append((v, "md5"))
            elif k_up == "SHA-1":
                out.append((v, "sha1"))
            elif k_up == "SHA-256":
                out.append((v, "sha256"))
    return out

# ----------------------- Dönüştürücüler -----------------------

def misp_type_to_ioc(t: str) -> Optional[str]:
    t = (t or "").lower()
    mapping = {
        "ip-src": "ip",
        "ip-dst": "ip",
        "ip-src|port": "ip",
        "ip-dst|port": "ip",
        "domain": "domain",
        "domain|ip": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "email-src": "email",
        "email-dst": "email",
        "email-src-display-name": "email",
        "filename": "filename",
    }
    return mapping.get(t)


def openioc_search_to_type(search: str) -> Optional[str]:
    s = (search or "").lower()
    if not s:
        return None
    if "portitem/port" in s or "processitem/port" in s:
        return None
    if "ipv4" in s or "address" in s:
        return "ip"
    if "url" in s:
        return "url"
    if "md5" in s:
        return "md5"
    if "sha1" in s:
        return "sha1"
    if "sha256" in s:
        return "sha256"
    if "email" in s:
        return "email"
    if any(k in s for k in ["domain", "dns"]):
        return "domain"
    return None


def normalize_tlp(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    s = v.strip().replace("TLP:", "").upper()
    mapping = {
        "WHITE": "TLP:CLEAR",
        "CLEAR": "TLP:CLEAR",
        "GREEN": "TLP:GREEN",
        "AMBER": "TLP:AMBER",
        "AMBER+STRICT": "TLP:AMBER+STRICT",
        "RED": "TLP:RED",
    }
    return mapping.get(s, v if v.upper().startswith("TLP:") else f"TLP:{s}")


def first_label(obj: Dict[str, Any]) -> Optional[str]:
    labels = obj.get("labels")
    if isinstance(labels, list) and labels:
        return str(labels[0])
    return None


def labels_to_tags(obj: Dict[str, Any]) -> List[str]:
    labels = obj.get("labels")
    return [str(x) for x in labels] if isinstance(labels, list) else []


def split_tags(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(t).strip() for t in x if str(t).strip()]
    if isinstance(x, str):
        parts = re.split(r"[,;|]", x)
        return [p.strip() for p in parts if p.strip()]
    return []


def try_int(x: Any) -> Optional[int]:
    try:
        if x is None or x == "":
            return None
        return int(float(x))
    except Exception:
        return None

# ----------------------- Çıktı üreticileri -----------------------

def write_jsonl(iocs: Iterable[IOC], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for i in iocs:
            f.write(json.dumps(asdict(i), ensure_ascii=False) + "\n")


def write_csv(iocs: Iterable[IOC], path: Path) -> None:
    rows = [asdict(i) for i in iocs]
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def to_stix_bundle(iocs: Iterable[IOC]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [],
    }
    for i in iocs:
        patt = ioc_to_stix_pattern(i)
        ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": i.first_seen or now,
            "modified": i.last_seen or i.first_seen or now,
            "pattern": patt,
            "pattern_type": "stix",
            "valid_from": i.first_seen or now,
            "name": f"IOC {i.type}",
            "confidence": i.confidence or 50,
            "labels": i.tags or [],
            "description": i.description or i.source,
        }
        if i.tlp:
            ind["object_marking_refs"] = [tlp_to_marking_id(i.tlp)]
        bundle["objects"].append(ind)
    used_tlps = {i.tlp for i in iocs if i.tlp}
    for tlp in used_tlps:
        bundle["objects"].append(tlp_marking_object(tlp))
    return bundle


def ioc_to_stix_pattern(i: IOC) -> str:
    t = i.type
    v = i.value.replace("'", "\\'")
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "url":
        return f"[url:value = '{v}']"
    if t == "ip":
        return f"[ipv4-addr:value = '{v}']"
    if t == "ipv6":
        return f"[ipv6-addr:value = '{v}']"
    if t == "email":
        return f"[email-addr:value = '{v}']"
    if t == "md5":
        return f"[file:hashes.'MD5' = '{v}']"
    if t == "sha1":
        return f"[file:hashes.'SHA-1' = '{v}']"
    if t == "sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    return f"[x-unknown:value = '{v}']"

TLP_IDS = {
    "TLP:CLEAR": "marking-definition--a2f2d16b-2dc1-4c0f-8d4c-4c5a5a8a1111",
    "TLP:GREEN": "marking-definition--961e8890-4b69-4d3a-9c2a-12d2dbe22222",
    "TLP:AMBER": "marking-definition--d1a0793f-9b4d-4b9a-8f16-03f7fbf33333",
    "TLP:AMBER+STRICT": "marking-definition--1b5b6a7c-7f3e-43b0-8a66-6e5c2f444444",
    "TLP:RED": "marking-definition--f1f7b1de-5a1b-4a4c-8a55-2c5555555555",
}

def tlp_to_marking_id(tlp: str) -> str:
    return TLP_IDS.get(tlp, TLP_IDS["TLP:AMBER"])


def tlp_marking_object(tlp: str) -> Dict[str, Any]:
    tid = tlp_to_marking_id(tlp)
    color = tlp.split(":", 1)[-1]
    return {
        "type": "marking-definition",
        "id": tid,
        "created": "2020-01-01T00:00:00Z",
        "definition_type": "tlp",
        "definition": {"tlp": color.lower()},
        "name": tlp,
    }

# ----------------------- Orkestrasyon -----------------------

def build_parser_for(path: Path, source: Optional[str], tlp: Optional[str]) -> BaseParser:
    fmt = detect_format(path)
    if fmt == "csv":
        return CSVParser(path, source, tlp)
    if fmt == "openioc":
        return OpenIOCParser(path, source, tlp)
    if fmt == "stix":
        return STIXParser(path, source, tlp)
    if fmt == "misp":
        return MISPParser(path, source, tlp)
    if fmt == "jsonlist":
        return JSONListParser(path, source, tlp)
    return TextParser(path, source, tlp)


def parse_files(paths: List[Path], source: Optional[str], tlp: Optional[str]) -> List[IOC]:
    out: List[IOC] = []
    for p in paths:
        parser = build_parser_for(p, source, tlp)
        for i in parser.parse():
            out.append(i)
    seen = set()
    uniq: List[IOC] = []
    for i in out:
        key = (i.value, i.type)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(i)
    return uniq

# ----------------------- CLI -----------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Çok formatlı CTI IOC parser")
    ap.add_argument("inputs", nargs="+", help="Girdi dosyaları (stix/misp/csv/xml/txt)")
    ap.add_argument("-o", "--output", help="Çıktı dosyası (varsayılan: stdout)")
    ap.add_argument("--out-format", choices=["jsonl", "csv", "stix"], default="jsonl", help="Çıktı formatı")
    ap.add_argument("--source", help="Varsayılan kaynak adı")
    ap.add_argument("--tlp", help="Varsayılan TLP (CLEAR, GREEN, AMBER, AMBER+STRICT, RED)")
    args = ap.parse_args(argv)

    paths = [Path(p) for p in args.inputs]
    for p in paths:
        if not p.exists():
            ap.error(f"Girdi bulunamadı: {p}")

    iocs = parse_files(paths, args.source, args.tlp)

    if args.out_format == "stix":
        bundle = to_stix_bundle(iocs)
        text = json.dumps(bundle, ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")
        return 0

    if args.output:
        if args.out_format == "jsonl":
            write_jsonl(iocs, Path(args.output))
        else:
            write_csv(iocs, Path(args.output))
    else:
        if args.out_format == "jsonl":
            for i in iocs:
                sys.stdout.write(json.dumps(asdict(i), ensure_ascii=False) + "\n")
        else:
            w = csv.DictWriter(sys.stdout, fieldnames=list(asdict(iocs[0]).keys()) if iocs else ["value","type"])
            w.writeheader()
            for r in (asdict(i) for i in iocs):
                w.writerow(r)
    return 0


def extract_tlp(obj: Dict[str, Any]) -> Optional[str]:
    labels = obj.get("labels")
    if isinstance(labels, list):
        for lbl in labels:
            if isinstance(lbl, str) and lbl.upper().startswith("TLP:"):
                return normalize_tlp(lbl)
    omr = obj.get("object_marking_refs")
    if isinstance(omr, list):
        inv = {v: k for k, v in TLP_IDS.items()}
        for mid in omr:
            if mid in inv:
                return inv[mid]
    return None

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Inspect Flipper NFC dump files and build safe marketing-tag assets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import shutil
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import qrcode
from qrcode.image.svg import SvgPathImage


NFC_CURRENT_FORMAT_VERSION = 4
MF_ULTRALIGHT_DATA_FORMAT_VERSION = 2
MF_ULTRALIGHT_SIGNATURE_SIZE = 32
MF_ULTRALIGHT_PAGE_SIZE = 4
DEFAULT_ATQA = bytes.fromhex("4400")
DEFAULT_SAK = bytes.fromhex("00")
DEFAULT_TEARING = bytes.fromhex("BD")

URI_PREFIXES = [
    "",
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cap://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:",
]


@dataclass(frozen=True)
class TagProfile:
    name: str
    pages_total: int
    user_page_end: int
    config_page: int
    cc_bytes: bytes
    mifare_version: bytes

    @property
    def capacity_bytes(self) -> int:
        return (self.user_page_end - 4 + 1) * MF_ULTRALIGHT_PAGE_SIZE

    @property
    def dynamic_lock_page(self) -> int:
        return self.config_page - 1


TAG_PROFILES = {
    "NTAG213": TagProfile(
        name="NTAG213",
        pages_total=45,
        user_page_end=39,
        config_page=41,
        cc_bytes=bytes.fromhex("E1101200"),
        mifare_version=bytes.fromhex("0004040201000F03"),
    ),
    "NTAG215": TagProfile(
        name="NTAG215",
        pages_total=135,
        user_page_end=129,
        config_page=131,
        cc_bytes=bytes.fromhex("E1103F00"),
        mifare_version=bytes.fromhex("0004040201001103"),
    ),
    "NTAG216": TagProfile(
        name="NTAG216",
        pages_total=231,
        user_page_end=225,
        config_page=227,
        cc_bytes=bytes.fromhex("E1106F00"),
        mifare_version=bytes.fromhex("0004040201001303"),
    ),
}


@dataclass
class NdefRecord:
    tnf: int
    type_name: str
    decoded: str
    raw_payload_hex: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tnf": self.tnf,
            "type_name": self.type_name,
            "decoded": self.decoded,
            "raw_payload_hex": self.raw_payload_hex,
        }


@dataclass
class TagDump:
    metadata: dict[str, str]
    pages: dict[int, bytes]
    ndef_records: list[NdefRecord]

    def summary(self) -> dict[str, Any]:
        return {
            "device_type": self.metadata.get("Device type", "unknown"),
            "uid": self.metadata.get("UID"),
            "atqa": self.metadata.get("ATQA"),
            "sak": self.metadata.get("SAK"),
            "page_count": len(self.pages),
            "ndef_records": [record.to_dict() for record in self.ndef_records],
            "metadata": self.metadata,
        }


def parse_hex_bytes(value: str) -> bytes:
    cleaned = value.replace(" ", "").strip()
    if len(cleaned) % 2 != 0:
        raise ValueError(f"invalid hex byte string: {value!r}")
    return bytes.fromhex(cleaned)


def parse_flipper_nfc(path: Path) -> TagDump:
    metadata: dict[str, str] = {}
    pages: dict[int, bytes] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line or line.startswith("#"):
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key.startswith("Page "):
            page_number = int(key.split()[1])
            pages[page_number] = parse_hex_bytes(value)
            continue
        metadata[key] = value

    payload = extract_ndef_bytes(pages)
    records = parse_ndef_message(payload) if payload else []
    return TagDump(metadata=metadata, pages=pages, ndef_records=records)


def extract_ndef_bytes(pages: dict[int, bytes], start_page: int = 4) -> bytes:
    if not pages:
        return b""

    data = bytearray()
    for page_number in sorted(pages):
        if page_number >= start_page:
            data.extend(pages[page_number])

    index = 0
    while index < len(data):
        tlv_type = data[index]
        if tlv_type == 0x00:
            index += 1
            continue
        if tlv_type == 0xFE:
            return b""
        if tlv_type != 0x03:
            index += 1
            continue
        if index + 1 >= len(data):
            return b""

        length = data[index + 1]
        payload_offset = index + 2
        if length == 0xFF:
            if index + 3 >= len(data):
                return b""
            length = (data[index + 2] << 8) | data[index + 3]
            payload_offset = index + 4

        return bytes(data[payload_offset : payload_offset + length])

    return b""


def parse_ndef_message(data: bytes) -> list[NdefRecord]:
    records: list[NdefRecord] = []
    offset = 0
    while offset < len(data):
        header = data[offset]
        offset += 1

        me = bool(header & 0x40)
        cf = bool(header & 0x20)
        sr = bool(header & 0x10)
        il = bool(header & 0x08)
        tnf = header & 0x07

        if cf:
            raise ValueError("chunked NDEF records are not supported")
        if offset >= len(data):
            break

        type_length = data[offset]
        offset += 1

        if sr:
            payload_length = data[offset]
            offset += 1
        else:
            payload_length = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4

        id_length = data[offset] if il else 0
        if il:
            offset += 1

        type_bytes = data[offset : offset + type_length]
        offset += type_length
        offset += id_length
        payload = data[offset : offset + payload_length]
        offset += payload_length

        type_name = type_bytes.decode("ascii", errors="replace")
        records.append(
            NdefRecord(
                tnf=tnf,
                type_name=type_name,
                decoded=decode_ndef_payload(tnf, type_name, payload),
                raw_payload_hex=payload.hex(),
            )
        )

        if me:
            break

    return records


def decode_ndef_payload(tnf: int, type_name: str, payload: bytes) -> str:
    if tnf != 0x01:
        return payload.hex()

    if type_name == "T" and payload:
        status = payload[0]
        language_length = status & 0x3F
        encoding = "utf-16" if status & 0x80 else "utf-8"
        return payload[1 + language_length :].decode(encoding, errors="replace")

    if type_name == "U" and payload:
        prefix_index = payload[0]
        prefix = URI_PREFIXES[prefix_index] if prefix_index < len(URI_PREFIXES) else ""
        return prefix + payload[1:].decode("utf-8", errors="replace")

    return payload.hex()


def build_text_record(text: str, lang: str = "en") -> bytes:
    lang_bytes = lang.encode("ascii")
    text_bytes = text.encode("utf-8")
    payload = bytes([len(lang_bytes)]) + lang_bytes + text_bytes
    return bytes([0xD1, 0x01, len(payload)]) + b"T" + payload


def build_uri_record(uri: str) -> bytes:
    best_prefix = ""
    prefix_index = 0
    for index, prefix in enumerate(URI_PREFIXES):
        if prefix and uri.startswith(prefix) and len(prefix) > len(best_prefix):
            best_prefix = prefix
            prefix_index = index
    payload = bytes([prefix_index]) + uri[len(best_prefix) :].encode("utf-8")
    return bytes([0xD1, 0x01, len(payload)]) + b"U" + payload


def normalize_extra_pairs(extras: dict[str, str] | list[str] | None) -> dict[str, str]:
    if extras is None:
        return {}
    if isinstance(extras, dict):
        return {str(key): str(value) for key, value in extras.items()}

    query: dict[str, str] = {}
    for item in extras:
        if "=" not in item:
            raise ValueError(f"invalid extra query pair: {item!r}")
        key, value = item.split("=", 1)
        query[key] = value
    return query


def parse_key_value_csv(value: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    if not value:
        return pairs
    for item in value.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if "=" not in candidate:
            raise ValueError(f"invalid key=value pair: {candidate!r}")
        key, pair_value = candidate.split("=", 1)
        pairs[key.strip()] = pair_value.strip()
    return pairs


def parse_pipe_list(value: str) -> list[str]:
    return [item.strip() for item in value.split("|") if item.strip()]


def resolve_path(path: str, relative_to: Path) -> Path:
    resolved = Path(path)
    if not resolved.is_absolute():
        resolved = relative_to / resolved
    return resolved.resolve()


def deterministic_code(seed: str, length: int = 7, alphabet: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789") -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).digest()
    number = int.from_bytes(digest, "big")
    chars = []
    base = len(alphabet)
    while len(chars) < length:
        number, remainder = divmod(number, base)
        chars.append(alphabet[remainder])
    return "".join(chars)


def build_redirect_url(base_url: str, code: str, mode: str = "path", query_param: str = "c") -> str:
    if mode == "query":
        parts = urlsplit(base_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[query_param] = code
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment)
        )
    return base_url.rstrip("/") + "/" + code


def load_csv_tags(csv_path: Path, defaults: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    tags = []
    defaults = defaults or {}
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if not any((value or "").strip() for value in row.values()):
                continue

            tag = deepcopy(defaults)
            tag["name"] = row.get("name") or tag.get("name")
            if not tag.get("name"):
                raise ValueError(f"CSV row in {csv_path} is missing a name")

            for field in [
                "slug",
                "content",
                "tag_type",
                "kind",
                "text",
                "lang",
                "source",
                "medium",
                "campaign",
                "base_url",
                "term",
                "ref",
                "redirect_code",
            ]:
                if row.get(field):
                    tag[field] = row[field].strip()

            extras = normalize_extra_pairs(tag.get("extras", {}))
            extras.update(parse_key_value_csv(row.get("extras", "")))
            if extras:
                tag["extras"] = extras

            interactive = deepcopy(tag.get("interactive", {}))
            if row.get("interactive_type"):
                interactive["type"] = row["interactive_type"].strip()
            if row.get("interactive_headline"):
                interactive["headline"] = row["interactive_headline"].strip()
            if row.get("interactive_prompt"):
                interactive["prompt"] = row["interactive_prompt"].strip()
            if row.get("interactive_options"):
                interactive["options"] = parse_pipe_list(row["interactive_options"])
            if row.get("interactive_outcomes"):
                interactive["outcomes"] = parse_pipe_list(row["interactive_outcomes"])
            if interactive:
                tag["interactive"] = interactive

            site_copy = deepcopy(tag.get("site_copy", {}))
            if row.get("site_headline"):
                site_copy["headline"] = row["site_headline"].strip()
            if row.get("site_subheadline"):
                site_copy["subheadline"] = row["site_subheadline"].strip()
            if site_copy:
                tag["site_copy"] = site_copy

            tags.append(tag)

    return tags


def load_campaign_config(config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    tags = list(config.get("tags", []))
    csv_imports = config.get("csv_import")
    if csv_imports:
        if isinstance(csv_imports, dict):
            csv_imports = [csv_imports]
        for import_spec in csv_imports:
            csv_path = resolve_path(import_spec["path"], config_path.parent)
            tags.extend(load_csv_tags(csv_path, import_spec.get("defaults")))
    config["tags"] = tags
    return config


def build_marketing_url(
    base_url: str,
    campaign: str | None,
    source: str,
    medium: str,
    content: str | None,
    term: str | None,
    extras: dict[str, str] | list[str] | None,
) -> str:
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["utm_source"] = source
    query["utm_medium"] = medium
    if campaign:
        query["utm_campaign"] = campaign
    if content:
        query["utm_content"] = content
    if term:
        query["utm_term"] = term
    query.update(normalize_extra_pairs(extras))

    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment)
    )


def wrap_tlv(message: bytes) -> bytes:
    if len(message) < 0xFF:
        return bytes([0x03, len(message)]) + message + b"\xFE"
    return b"\x03\xFF" + len(message).to_bytes(2, "big") + message + b"\xFE"


def format_pages(data: bytes, start_page: int = 4) -> list[dict[str, str]]:
    padded = bytearray(data)
    while len(padded) % MF_ULTRALIGHT_PAGE_SIZE != 0:
        padded.append(0x00)

    pages = []
    for index in range(0, len(padded), MF_ULTRALIGHT_PAGE_SIZE):
        page_number = start_page + (index // MF_ULTRALIGHT_PAGE_SIZE)
        chunk = bytes(padded[index : index + MF_ULTRALIGHT_PAGE_SIZE])
        pages.append({"page": str(page_number), "bytes": chunk.hex(" ").upper()})
    return pages


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "tag"


def generate_uid(seed: str) -> bytes:
    digest = hashlib.sha1(seed.encode("utf-8")).digest()
    uid = bytearray(digest[:7])
    uid[0] = 0x04
    return bytes(uid)


def build_flipper_pages(message: bytes, profile: TagProfile, uid: bytes) -> dict[int, bytes]:
    tlv = wrap_tlv(message)
    if len(tlv) > profile.capacity_bytes:
        raise ValueError(
            f"payload is {len(tlv)} bytes but {profile.name} only fits {profile.capacity_bytes}; "
            "use a shorter URL, a redirect domain, or a larger tag such as NTAG215"
        )
    if len(uid) != 7:
        raise ValueError("only 7-byte UID generation is supported for marketing tags")

    pages = {page: bytes(MF_ULTRALIGHT_PAGE_SIZE) for page in range(profile.pages_total)}
    bcc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
    pages[0] = bytes([uid[0], uid[1], uid[2], bcc0])
    pages[1] = uid[3:7]
    pages[2] = bytes([bcc1, 0x48, 0x00, 0x00])
    pages[3] = profile.cc_bytes

    user_area = bytearray(profile.capacity_bytes)
    user_area[: len(tlv)] = tlv
    for index in range(0, len(user_area), MF_ULTRALIGHT_PAGE_SIZE):
        page_number = 4 + (index // MF_ULTRALIGHT_PAGE_SIZE)
        pages[page_number] = bytes(user_area[index : index + MF_ULTRALIGHT_PAGE_SIZE])

    pages[profile.dynamic_lock_page] = bytes.fromhex("00000000")
    pages[profile.config_page] = bytes.fromhex("000000FF")
    pages[profile.config_page + 1] = bytes.fromhex("00050000")
    pages[profile.config_page + 2] = bytes.fromhex("FFFFFFFF")
    pages[profile.config_page + 3] = bytes.fromhex("00000000")
    return pages


def render_flipper_nfc(message: bytes, profile: TagProfile, uid_seed: str) -> str:
    uid = generate_uid(uid_seed)
    pages = build_flipper_pages(message, profile, uid)
    signature = bytes(MF_ULTRALIGHT_SIGNATURE_SIZE)

    lines = [
        "Filetype: Flipper NFC device",
        f"Version: {NFC_CURRENT_FORMAT_VERSION}",
        "# Device type can be ISO14443-3A, Mifare Classic, NTAG/Ultralight, Bank card",
        "Device type: NTAG/Ultralight",
        "# UID is common for all formats",
        f"UID: {uid.hex(' ').upper()}",
        "# ISO14443-3A specific data",
        f"ATQA: {DEFAULT_ATQA.hex(' ').upper()}",
        f"SAK: {DEFAULT_SAK.hex(' ').upper()}",
        "# NTAG/Ultralight specific data",
        f"Data format version: {MF_ULTRALIGHT_DATA_FORMAT_VERSION}",
        f"NTAG/Ultralight type: {profile.name}",
        f"Signature: {signature.hex(' ').upper()}",
        f"Mifare version: {profile.mifare_version.hex(' ').upper()}",
        "Counter 0: 0",
        f"Tearing 0: {DEFAULT_TEARING.hex(' ').upper()}",
        "Counter 1: 0",
        f"Tearing 1: {DEFAULT_TEARING.hex(' ').upper()}",
        "Counter 2: 0",
        f"Tearing 2: {DEFAULT_TEARING.hex(' ').upper()}",
        f"Pages total: {profile.pages_total}",
        f"Pages read: {profile.pages_total}",
    ]
    lines.extend(
        f"Page {page}: {pages[page].hex(' ').upper()}" for page in range(profile.pages_total)
    )
    lines.append("Failed authentication attempts: 0")
    return "\n".join(lines) + "\n"


def inspect_command(path: Path, as_json: bool) -> int:
    dump = parse_flipper_nfc(path)
    summary = dump.summary()
    if as_json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"Device type: {summary['device_type']}")
    print(f"UID: {summary.get('uid') or 'unknown'}")
    if summary.get("atqa"):
        print(f"ATQA: {summary['atqa']}")
    if summary.get("sak"):
        print(f"SAK: {summary['sak']}")
    print(f"Pages found: {summary['page_count']}")
    if dump.ndef_records:
        print("NDEF records:")
        for index, record in enumerate(dump.ndef_records, start=1):
            print(f"  {index}. {record.type_name}: {record.decoded}")
    else:
        print("NDEF records: none detected")
    return 0


def build_command(message: bytes, record_kind: str) -> int:
    tlv = wrap_tlv(message)
    print(
        json.dumps(
            {
                "record_kind": record_kind,
                "ndef_hex": message.hex(" ").upper(),
                "tlv_hex": tlv.hex(" ").upper(),
                "pages_from_4": format_pages(tlv),
            },
            indent=2,
        )
    )
    return 0


def export_flipper_command(
    message: bytes,
    profile_name: str,
    output_path: Path,
    uid_seed: str,
) -> int:
    profile = TAG_PROFILES[profile_name]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_flipper_nfc(message, profile, uid_seed), encoding="utf-8")
    print(str(output_path))
    return 0


def write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json_file(path: Path, payload: Any) -> None:
    write_text_file(path, json.dumps(payload, indent=2))


def write_csv_manifest(path: Path, tags: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "name",
        "slug",
        "kind",
        "tag_type",
        "content",
        "final_url",
        "redirect_target_url",
        "redirect_code",
        "relative_flipper_file",
        "relative_qr_file",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for tag in tags:
            writer.writerow({field: tag.get(field, "") for field in fieldnames})


def generate_qr_svg(data: str) -> str:
    image = qrcode.make(data, image_factory=SvgPathImage, box_size=10, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def generate_qr_assets(qr_dir: Path, tags: list[dict[str, Any]], bundle_dir: Path) -> None:
    qr_dir.mkdir(parents=True, exist_ok=True)
    for tag in tags:
        svg_path = qr_dir / f"{tag['slug']}.svg"
        write_text_file(svg_path, generate_qr_svg(tag["final_url"]))
        tag["relative_qr_file"] = str(svg_path.relative_to(bundle_dir))


def print_sheet_html(campaign_name: str, tags: list[dict[str, Any]]) -> str:
    cards = []
    for tag in tags:
        qr_path = "../" + tag["relative_qr_file"].replace("\\", "/")
        destination = tag.get("redirect_target_url") or tag["final_url"]
        cards.append(
            f"""
      <article class="card">
        <div class="topline">{campaign_name}</div>
        <h2>{tag['name']}</h2>
        <p class="slug">{tag['slug']}</p>
        <img src="{qr_path}" alt="QR code for {tag['name']}">
        <dl>
          <div><dt>Tag URL</dt><dd>{tag['final_url']}</dd></div>
          <div><dt>Landing URL</dt><dd>{destination}</dd></div>
          <div><dt>Flipper File</dt><dd>{tag['relative_flipper_file']}</dd></div>
        </dl>
      </article>"""
        )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{campaign_name} Deployment Sheet</title>
    <style>
      @page {{ size: letter portrait; margin: 0.5in; }}
      body {{ font-family: "Space Grotesk", sans-serif; margin: 0; color: #1a2522; }}
      .sheet {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 18px; }}
      .card {{ border: 1px solid #d9d4c6; border-radius: 18px; padding: 18px; break-inside: avoid; }}
      .topline {{ text-transform: uppercase; font-size: 10px; letter-spacing: 0.14em; color: #6d7066; }}
      h2 {{ margin: 8px 0 2px; font-size: 24px; line-height: 1.02; }}
      .slug {{ margin: 0 0 12px; color: #5d655e; }}
      img {{ width: 180px; height: 180px; display: block; margin: 8px 0 14px; }}
      dl {{ margin: 0; display: grid; gap: 10px; }}
      dt {{ font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
      dd {{ margin: 4px 0 0; font-size: 12px; overflow-wrap: anywhere; }}
    </style>
  </head>
  <body>
    <main class="sheet">
      {"".join(cards)}
    </main>
  </body>
</html>
"""


def redirect_handler_js() -> str:
    return """import fs from "node:fs/promises";

const REDIRECT_MAP_PATH = new URL("./redirects/redirect-map.json", import.meta.url);

export default async function handler(req, res) {
  const map = JSON.parse(await fs.readFile(REDIRECT_MAP_PATH, "utf8"));
  const code = req.query.c || req.url.split("/").filter(Boolean).at(-1);
  if (!code || !map.codes[code]) {
    res.statusCode = 404;
    res.end("Unknown redirect code");
    return;
  }

  res.statusCode = 302;
  res.setHeader("Location", map.codes[code].target_url);
  res.end();
}
"""


def hubspot_proxy_js() -> str:
    return """export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.end("Method not allowed");
    return;
  }

  const portalId = process.env.HUBSPOT_PORTAL_ID;
  const formId = process.env.HUBSPOT_FORM_ID;
  if (!portalId || !formId) {
    res.statusCode = 500;
    res.end("Missing HUBSPOT_PORTAL_ID or HUBSPOT_FORM_ID");
    return;
  }

  const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  const lead = body.lead || {};
  const fields = [
    { name: "firstname", value: lead.name || "" },
    { name: "email", value: lead.email || "" },
    { name: "company", value: lead.company || "" },
    { name: "message", value: lead.notes || "" },
    { name: "nfc_tag_slug", value: body.tag || "" },
    { name: "nfc_campaign", value: body.campaign || "" }
  ];

  const response = await fetch(
    `https://api.hsforms.com/submissions/v3/integration/submit/${portalId}/${formId}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fields,
        context: {
          pageUri: body.final_url || "",
          pageName: body.campaign || "NFC Campaign"
        }
      })
    }
  );

  const text = await response.text();
  res.statusCode = response.status;
  res.setHeader("Content-Type", "application/json");
  res.end(text);
}
"""


def airtable_proxy_js() -> str:
    return """export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.end("Method not allowed");
    return;
  }

  const token = process.env.AIRTABLE_PAT;
  const baseId = process.env.AIRTABLE_BASE_ID;
  const tableName = process.env.AIRTABLE_TABLE_NAME;
  if (!token || !baseId || !tableName) {
    res.statusCode = 500;
    res.end("Missing AIRTABLE_PAT, AIRTABLE_BASE_ID, or AIRTABLE_TABLE_NAME");
    return;
  }

  const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  const lead = body.lead || {};
  const payload = {
    records: [
      {
        fields: {
          Name: lead.name || "",
          Email: lead.email || "",
          Company: lead.company || "",
          Notes: lead.notes || "",
          Campaign: body.campaign || "",
          Tag: body.tag || "",
          FinalURL: body.final_url || "",
          SubmittedAt: body.submitted_at || ""
        }
      }
    ]
  };

  const response = await fetch(`https://api.airtable.com/v0/${baseId}/${encodeURIComponent(tableName)}`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const text = await response.text();
  res.statusCode = response.status;
  res.setHeader("Content-Type", "application/json");
  res.end(text);
}
"""


def integrations_readme() -> str:
    return """# Integration Templates

This folder contains optional templates for wiring the generated microsite into common marketing tools.

- `hubspot-proxy.js`: serverless example that forwards lead payloads into a HubSpot form using `HUBSPOT_PORTAL_ID` and `HUBSPOT_FORM_ID`.
- `airtable-proxy.js`: serverless example that forwards lead payloads into Airtable using `AIRTABLE_PAT`, `AIRTABLE_BASE_ID`, and `AIRTABLE_TABLE_NAME`.
- `redirect-handler.js`: serverless example that reads `redirects/redirect-map.json` and resolves short NFC redirect codes.

For HubSpot, the generated site can also submit directly from the browser when `campaign.site.integration.provider` is `hubspot` and the required form IDs are present.
"""


def generate_integrations(bundle_dir: Path, redirect_enabled: bool) -> None:
    integrations_dir = bundle_dir / "integrations"
    integrations_dir.mkdir(parents=True, exist_ok=True)
    write_text_file(integrations_dir / "README.md", integrations_readme())
    write_text_file(integrations_dir / "hubspot-proxy.js", hubspot_proxy_js())
    write_text_file(integrations_dir / "airtable-proxy.js", airtable_proxy_js())
    if redirect_enabled:
        write_text_file(integrations_dir / "redirect-handler.js", redirect_handler_js())


def build_site_payload(config: dict[str, Any], manifest_tags: list[dict[str, Any]]) -> dict[str, Any]:
    site = config["campaign"].get("site", {})
    campaign_slug = config["campaign"].get("slug") or slugify(config["campaign"]["name"])
    integration = site.get("integration", {})
    lead_endpoint = site.get("lead_endpoint", "")
    if integration.get("provider") == "airtable" and integration.get("endpoint"):
        lead_endpoint = integration["endpoint"]
    return {
        "campaign": {
            "name": config["campaign"]["name"],
            "slug": campaign_slug,
            "lead_endpoint": lead_endpoint,
            "integration": integration,
            "title": site.get("title", config["campaign"]["name"]),
            "headline": site.get("headline", "Tap to unlock the next move."),
            "subheadline": site.get(
                "subheadline",
                "These NFC stickers can launch a lightweight interactive scene and lead form.",
            ),
            "cta_label": site.get("cta_label", "Send me the follow-up"),
            "success_message": site.get(
                "success_message",
                "You are in. We saved your details for the follow-up.",
            ),
            "privacy_blurb": site.get(
                "privacy_blurb",
                "Only the details in this form are stored; campaign and tag metadata are attached automatically.",
            ),
        },
        "tags": manifest_tags,
    }


def site_index_html() -> str:
    return """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>FZero NFC Campaign</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:wght@500;700&family=Space+Grotesk:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <p class="eyebrow" id="campaign-name">NFC Campaign</p>
        <h1 id="headline">Tap to unlock the next move.</h1>
        <p class="lede" id="subheadline">These NFC stickers can launch a lightweight interactive scene and lead form.</p>
        <div class="tag-chip" id="tag-chip">Waiting for tag context</div>
      </section>

      <section class="panel interaction-panel">
        <div class="panel-copy">
          <p class="panel-label">Interactive Moment</p>
          <h2 id="interactive-headline">A small tap should do something memorable.</h2>
          <p id="interactive-prompt">This page swaps in tag-specific prompts from the generated campaign data.</p>
        </div>
        <div id="experience-root" class="experience-root"></div>
      </section>

      <section class="panel lead-panel">
        <div class="panel-copy">
          <p class="panel-label">Lead Capture</p>
          <h2>Keep the conversation moving.</h2>
          <p id="privacy-blurb">Only the details in this form are stored; campaign and tag metadata are attached automatically.</p>
        </div>
        <form id="lead-form" class="lead-form">
          <label>
            Name
            <input type="text" name="name" placeholder="Avery Stone" required>
          </label>
          <label>
            Email
            <input type="email" name="email" placeholder="avery@example.com" required>
          </label>
          <label>
            Company
            <input type="text" name="company" placeholder="Northwind Studio">
          </label>
          <label>
            What caught your attention?
            <textarea name="notes" rows="4" placeholder="The game, the sticker trail, the demo wall..."></textarea>
          </label>
          <button type="submit" id="submit-label">Send me the follow-up</button>
          <p id="form-status" class="form-status" aria-live="polite"></p>
        </form>
      </section>
    </main>
    <script type="module" src="app.js"></script>
  </body>
</html>
"""


def site_styles_css() -> str:
    return """:root {
  --paper: #f7f0df;
  --ink: #172321;
  --coral: #ef8354;
  --gold: #f2c14e;
  --teal: #2d6a6d;
  --mint: #cde7da;
  --panel: rgba(255, 250, 238, 0.82);
  --line: rgba(23, 35, 33, 0.12);
  --shadow: 0 22px 50px rgba(23, 35, 33, 0.12);
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  background:
    radial-gradient(circle at top left, rgba(242, 193, 78, 0.38), transparent 32%),
    radial-gradient(circle at bottom right, rgba(45, 106, 109, 0.26), transparent 28%),
    linear-gradient(160deg, #fff9ef 0%, #f4e8d2 44%, #ead7bf 100%);
  font-family: "Space Grotesk", sans-serif;
}

.shell {
  width: min(1120px, calc(100% - 32px));
  margin: 0 auto;
  padding: 40px 0 56px;
  display: grid;
  gap: 18px;
}

.hero,
.panel {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 28px;
  background: var(--panel);
  backdrop-filter: blur(10px);
  box-shadow: var(--shadow);
}

.hero {
  padding: 36px;
}

.hero::after,
.panel::after {
  content: "";
  position: absolute;
  inset: auto -60px -80px auto;
  width: 180px;
  height: 180px;
  border-radius: 50%;
  background: linear-gradient(135deg, rgba(239, 131, 84, 0.18), rgba(45, 106, 109, 0.08));
}

.eyebrow,
.panel-label,
.tag-chip {
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-size: 0.78rem;
}

.eyebrow,
.panel-label {
  margin: 0 0 12px;
  color: rgba(23, 35, 33, 0.72);
}

h1,
h2 {
  margin: 0;
  font-family: "Fraunces", serif;
  line-height: 0.96;
}

h1 {
  max-width: 10ch;
  font-size: clamp(3rem, 8vw, 6.6rem);
}

h2 {
  font-size: clamp(2rem, 4vw, 3.4rem);
}

.lede,
#interactive-prompt,
#privacy-blurb {
  max-width: 60ch;
  margin: 14px 0 0;
  line-height: 1.55;
  color: rgba(23, 35, 33, 0.82);
}

.tag-chip {
  display: inline-flex;
  margin-top: 24px;
  padding: 10px 14px;
  border-radius: 999px;
  background: rgba(23, 35, 33, 0.06);
}

.panel {
  display: grid;
  gap: 18px;
  padding: 28px;
}

.interaction-panel {
  grid-template-columns: minmax(0, 1.1fr) minmax(280px, 0.9fr);
}

.experience-root {
  display: grid;
  gap: 12px;
  align-content: start;
}

.card-row {
  display: grid;
  gap: 12px;
}

.reward-card,
.choice-button {
  border: 1px solid var(--line);
  border-radius: 20px;
  padding: 16px 18px;
  background: rgba(255, 255, 255, 0.56);
}

.choice-button,
.spin-button,
.lead-form button {
  font: inherit;
  cursor: pointer;
  transition: transform 160ms ease, box-shadow 160ms ease, background 160ms ease;
}

.choice-button:hover,
.spin-button:hover,
.lead-form button:hover {
  transform: translateY(-1px);
  box-shadow: 0 14px 26px rgba(23, 35, 33, 0.12);
}

.spin-button,
.lead-form button {
  border: 0;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--coral), var(--gold));
  color: #fffdf7;
  padding: 14px 18px;
}

.lead-form {
  display: grid;
  gap: 14px;
}

.lead-form label {
  display: grid;
  gap: 8px;
  font-size: 0.94rem;
}

.lead-form input,
.lead-form textarea {
  width: 100%;
  border: 1px solid rgba(23, 35, 33, 0.18);
  border-radius: 16px;
  padding: 14px 16px;
  font: inherit;
  color: var(--ink);
  background: rgba(255, 255, 255, 0.7);
}

.form-status {
  min-height: 1.4em;
  margin: 0;
  color: var(--teal);
}

.reveal {
  display: grid;
  gap: 12px;
}

.reveal-output {
  min-height: 88px;
  padding: 18px;
  border-radius: 22px;
  background: linear-gradient(160deg, rgba(205, 231, 218, 0.72), rgba(255, 255, 255, 0.72));
  border: 1px solid rgba(45, 106, 109, 0.18);
}

@media (max-width: 820px) {
  .shell {
    width: min(100% - 20px, 1120px);
    padding-top: 20px;
  }

  .hero,
  .panel {
    border-radius: 22px;
  }

  .interaction-panel {
    grid-template-columns: 1fr;
  }

  h1 {
    max-width: 12ch;
  }
}
"""


def site_app_js() -> str:
    return """const params = new URLSearchParams(window.location.search);
let currentInteraction = null;

async function loadCampaign() {
  const response = await fetch("campaign-data.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Unable to load campaign-data.json");
  }
  return response.json();
}

function findTag(data) {
  const requested = params.get("tag") || params.get("ref") || params.get("utm_content");
  if (!requested) {
    return data.tags[0] || null;
  }

  return (
    data.tags.find((tag) => {
      if (tag.slug === requested || tag.content === requested) {
        return true;
      }
      return Object.values(tag.extra_params || {}).includes(requested);
    }) || data.tags[0] || null
  );
}

function setCopy(data, tag) {
  document.title = data.campaign.title;
  document.getElementById("campaign-name").textContent = data.campaign.name;
  document.getElementById("headline").textContent =
    (tag && tag.site_copy && tag.site_copy.headline) || data.campaign.headline;
  document.getElementById("subheadline").textContent =
    (tag && tag.site_copy && tag.site_copy.subheadline) || data.campaign.subheadline;
  document.getElementById("tag-chip").textContent = tag
    ? `Live tag: ${tag.name}`
    : "Generic campaign mode";
  document.getElementById("interactive-headline").textContent =
    (tag && tag.interactive && tag.interactive.headline) || "A small tap should do something memorable.";
  document.getElementById("interactive-prompt").textContent =
    (tag && tag.interactive && tag.interactive.prompt) ||
    "This page swaps in tag-specific prompts from the generated campaign data.";
  document.getElementById("submit-label").textContent = data.campaign.cta_label;
  document.getElementById("privacy-blurb").textContent = data.campaign.privacy_blurb;
}

function setStatus(message, isError = false) {
  const node = document.getElementById("form-status");
  node.textContent = message;
  node.style.color = isError ? "#b4432f" : "#2d6a6d";
}

function renderReveal(root, interactive) {
  const outcomes = interactive.outcomes && interactive.outcomes.length
    ? interactive.outcomes
    : ["VIP demo slot", "Sticker pack", "Behind-the-scenes link"];
  root.innerHTML = `
    <div class="reveal">
      <button class="spin-button" type="button">Reveal what this tag unlocks</button>
      <div class="reveal-output">Press reveal to surface a tag-specific reward or prompt.</div>
    </div>
  `;
  const button = root.querySelector("button");
  const output = root.querySelector(".reveal-output");
  button.addEventListener("click", () => {
    const choice = outcomes[Math.floor(Math.random() * outcomes.length)];
    currentInteraction = { type: "reveal", choice };
    output.textContent = choice;
  });
}

function renderChoices(root, interactive) {
  const options = interactive.options && interactive.options.length
    ? interactive.options
    : ["Book a demo", "Grab the deck", "Get the follow-up link"];
  root.innerHTML = `<div class="card-row"></div>`;
  const row = root.querySelector(".card-row");
  options.forEach((option) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "choice-button";
    button.textContent = option;
    button.addEventListener("click", () => {
      currentInteraction = { type: interactive.type || "choice", choice: option };
      [...row.children].forEach((child) => {
        child.style.background = "rgba(255, 255, 255, 0.56)";
      });
      button.style.background = "rgba(205, 231, 218, 0.9)";
    });
    row.appendChild(button);
  });
}

function renderExperience(tag) {
  const root = document.getElementById("experience-root");
  root.innerHTML = "";
  const interactive = (tag && tag.interactive) || { type: "reveal" };
  if (interactive.type === "quiz" || interactive.type === "pick") {
    renderChoices(root, interactive);
    return;
  }
  renderReveal(root, interactive);
}

async function submitLead(event, data, tag) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const payload = {
    submitted_at: new Date().toISOString(),
    campaign: data.campaign.slug,
    tag: tag ? tag.slug : null,
    final_url: tag ? tag.final_url : null,
    interaction: currentInteraction,
    query: Object.fromEntries(params.entries()),
    lead: {
      name: formData.get("name"),
      email: formData.get("email"),
      company: formData.get("company"),
      notes: formData.get("notes"),
    },
  };

  setStatus("Submitting...");

  try {
    if (data.campaign.integration && data.campaign.integration.provider === "hubspot") {
      const portalId = data.campaign.integration.portal_id;
      const formId = data.campaign.integration.form_id;
      const fieldMap = data.campaign.integration.field_map || {
        name: "firstname",
        email: "email",
        company: "company",
        notes: "message"
      };
      if (!portalId || !formId) {
        throw new Error("HubSpot integration requires portal_id and form_id.");
      }
      const fields = [
        { name: fieldMap.name || "firstname", value: payload.lead.name || "" },
        { name: fieldMap.email || "email", value: payload.lead.email || "" },
        { name: fieldMap.company || "company", value: payload.lead.company || "" },
        { name: fieldMap.notes || "message", value: payload.lead.notes || "" },
        { name: "nfc_tag_slug", value: payload.tag || "" },
        { name: "nfc_campaign", value: payload.campaign || "" }
      ];
      const response = await fetch(
        `https://api.hsforms.com/submissions/v3/integration/submit/${portalId}/${formId}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fields,
            context: {
              pageUri: window.location.href,
              pageName: data.campaign.title
            }
          })
        }
      );
      if (!response.ok) {
        throw new Error(`HubSpot returned ${response.status}`);
      }
    } else if (data.campaign.lead_endpoint) {
      const response = await fetch(data.campaign.lead_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        throw new Error(`Lead endpoint returned ${response.status}`);
      }
    } else {
      const existing = JSON.parse(localStorage.getItem("fzero_leads") || "[]");
      existing.push(payload);
      localStorage.setItem("fzero_leads", JSON.stringify(existing));
    }

    form.reset();
    setStatus(data.campaign.success_message);
  } catch (error) {
    setStatus(error.message || "Unable to submit lead.", true);
  }
}

async function init() {
  try {
    const data = await loadCampaign();
    const tag = findTag(data);
    setCopy(data, tag);
    renderExperience(tag);
    document
      .getElementById("lead-form")
      .addEventListener("submit", (event) => submitLead(event, data, tag));
  } catch (error) {
    setStatus(error.message || "Unable to initialize page.", true);
  }
}

init();
"""


def generate_site(site_dir: Path, payload: dict[str, Any]) -> None:
    site_dir.mkdir(parents=True, exist_ok=True)
    write_text_file(site_dir / "index.html", site_index_html())
    write_text_file(site_dir / "styles.css", site_styles_css())
    write_text_file(site_dir / "app.js", site_app_js())
    write_text_file(site_dir / "campaign-data.json", json.dumps(payload, indent=2))


def build_campaign_bundle(
    config_path: Path,
    out_dir: Path,
    flipper_root: Path | None = None,
) -> dict[str, Any]:
    config = load_campaign_config(config_path)
    campaign = config["campaign"]
    campaign_name = campaign["name"]
    campaign_slug = campaign.get("slug") or slugify(campaign_name)
    default_tag_type = campaign.get("default_tag_type", "NTAG213")
    redirect_config = campaign.get("redirect", {})
    redirect_enabled = bool(redirect_config.get("enabled"))
    redirect_mode = redirect_config.get("mode", "path")
    redirect_query_param = redirect_config.get("query_param", "c")
    redirect_base_url = redirect_config.get("base_url", "").strip()

    bundle_dir = out_dir / campaign_slug
    site_dir = bundle_dir / "site"
    qr_dir = bundle_dir / "qr"
    print_dir = bundle_dir / "print"
    redirects_dir = bundle_dir / "redirects"
    flipper_sd_dir = bundle_dir / "flipper_sd" / "ext" / "nfc" / campaign_slug
    flipper_sd_dir.mkdir(parents=True, exist_ok=True)

    manifest_tags = []
    redirect_codes: dict[str, dict[str, Any]] = {}
    for index, tag in enumerate(config["tags"], start=1):
        tag_name = tag["name"]
        tag_slug = tag.get("slug") or slugify(tag_name)
        profile_name = tag.get("tag_type", default_tag_type)
        if profile_name not in TAG_PROFILES:
            raise ValueError(f"unsupported tag type: {profile_name}")

        site_copy = tag.get("site_copy", {})
        interactive = tag.get("interactive", {"type": "reveal"})
        source = tag.get("source", campaign.get("default_source", "nfc"))
        medium = tag.get("medium", campaign.get("default_medium", "tag"))
        content = tag.get("content", tag_slug)
        extras = normalize_extra_pairs(tag.get("extras", {}))
        extras.setdefault("tag", tag_slug)
        extras.setdefault("experience", interactive.get("type", "reveal"))
        if tag.get("ref"):
            extras.setdefault("ref", tag["ref"])

        kind = tag.get("kind", "lead_url")
        final_url = None
        redirect_target_url = None
        redirect_code = None
        if kind == "text":
            message = build_text_record(tag["text"], tag.get("lang", "en"))
        else:
            base_url = tag.get("base_url", campaign["base_url"])
            redirect_target_url = build_marketing_url(
                base_url=base_url,
                campaign=tag.get("campaign", campaign_slug),
                source=source,
                medium=medium,
                content=content,
                term=tag.get("term"),
                extras=extras,
            )
            final_url = redirect_target_url
            if redirect_enabled:
                if not redirect_base_url:
                    raise ValueError("campaign.redirect.base_url is required when redirect.enabled is true")
                redirect_code = tag.get("redirect_code") or deterministic_code(
                    f"{campaign_slug}:{tag_slug}:{content}",
                    length=int(redirect_config.get("code_length", 7)),
                    alphabet=redirect_config.get(
                        "alphabet", "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                    ),
                )
                final_url = build_redirect_url(
                    redirect_base_url,
                    redirect_code,
                    mode=redirect_mode,
                    query_param=redirect_query_param,
                )
                redirect_codes[redirect_code] = {
                    "tag": tag_slug,
                    "target_url": redirect_target_url,
                    "short_url": final_url,
                }
            message = build_uri_record(final_url)

        profile = TAG_PROFILES[profile_name]
        output_path = flipper_sd_dir / f"{tag_slug}.nfc"
        uid_seed = f"{campaign_slug}:{index}:{tag_slug}"
        output_path.write_text(render_flipper_nfc(message, profile, uid_seed), encoding="utf-8")

        manifest_tags.append(
            {
                "name": tag_name,
                "slug": tag_slug,
                "kind": kind,
                "tag_type": profile_name,
                "content": content,
                "final_url": final_url,
                "redirect_target_url": redirect_target_url,
                "redirect_code": redirect_code,
                "relative_flipper_file": str(output_path.relative_to(bundle_dir)),
                "interactive": interactive,
                "site_copy": site_copy,
                "extra_params": extras,
            }
        )

    generate_qr_assets(qr_dir, manifest_tags, bundle_dir)
    site_payload = build_site_payload(config, manifest_tags)
    generate_site(site_dir, site_payload)
    generate_integrations(bundle_dir, redirect_enabled)

    if redirect_enabled:
        redirects_dir.mkdir(parents=True, exist_ok=True)
        write_json_file(
            redirects_dir / "redirect-map.json",
            {
                "campaign": campaign_name,
                "slug": campaign_slug,
                "mode": redirect_mode,
                "base_url": redirect_base_url,
                "codes": redirect_codes,
            },
        )

    print_dir.mkdir(parents=True, exist_ok=True)
    write_text_file(print_dir / "deployment-sheet.html", print_sheet_html(campaign_name, manifest_tags))

    manifest = {
        "campaign": campaign_name,
        "slug": campaign_slug,
        "site": str(site_dir.relative_to(bundle_dir)),
        "qr": str(qr_dir.relative_to(bundle_dir)),
        "print": str(print_dir.relative_to(bundle_dir)),
        "integrations": "integrations",
        "flipper_sd_path": str(flipper_sd_dir.relative_to(bundle_dir)),
        "redirects": str(redirects_dir.relative_to(bundle_dir)) if redirect_enabled else None,
        "tags": manifest_tags,
    }
    write_json_file(bundle_dir / "manifest.json", manifest)
    write_csv_manifest(bundle_dir / "manifest.csv", manifest_tags)

    if flipper_root is not None:
        destination = flipper_root / "ext" / "nfc" / campaign_slug
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(flipper_sd_dir, destination, dirs_exist_ok=True)

    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect Flipper NFC dumps and build marketing-friendly NFC payloads."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="inspect a Flipper .nfc dump")
    inspect_parser.add_argument("path", type=Path)
    inspect_parser.add_argument("--json", action="store_true", help="print JSON output")

    text_parser = subparsers.add_parser("build-text", help="build a text NDEF record")
    text_parser.add_argument("text")
    text_parser.add_argument("--lang", default="en")

    url_parser = subparsers.add_parser("build-url", help="build a URL NDEF record")
    url_parser.add_argument("url")

    lead_parser = subparsers.add_parser("build-lead-url", help="build a trackable URL record")
    lead_parser.add_argument("base_url")
    lead_parser.add_argument("--campaign")
    lead_parser.add_argument("--source", default="nfc")
    lead_parser.add_argument("--medium", default="tag")
    lead_parser.add_argument("--content")
    lead_parser.add_argument("--term")
    lead_parser.add_argument("--extra", action="append", default=[])

    flipper_parser = subparsers.add_parser(
        "export-flipper-url",
        help="write a Flipper-compatible .nfc file for a URL payload",
    )
    flipper_parser.add_argument("url")
    flipper_parser.add_argument("output", type=Path)
    flipper_parser.add_argument("--tag-type", default="NTAG213", choices=sorted(TAG_PROFILES))
    flipper_parser.add_argument("--uid-seed", default="fzero")

    campaign_parser = subparsers.add_parser(
        "build-campaign",
        help="build batch Flipper files plus a static landing page from a JSON config",
    )
    campaign_parser.add_argument("config", type=Path)
    campaign_parser.add_argument("--out", type=Path, default=Path("dist"))
    campaign_parser.add_argument(
        "--flipper-root",
        type=Path,
        help="optional mounted SD root; generated ext/nfc files are copied there too",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "inspect":
        return inspect_command(args.path, args.json)
    if args.command == "build-text":
        return build_command(build_text_record(args.text, args.lang), "text")
    if args.command == "build-url":
        return build_command(build_uri_record(args.url), "url")
    if args.command == "build-lead-url":
        final_url = build_marketing_url(
            base_url=args.base_url,
            campaign=args.campaign,
            source=args.source,
            medium=args.medium,
            content=args.content,
            term=args.term,
            extras=args.extra,
        )
        payload = build_uri_record(final_url)
        print(
            json.dumps(
                {
                    "record_kind": "lead_url",
                    "final_url": final_url,
                    "ndef_hex": payload.hex(" ").upper(),
                    "tlv_hex": wrap_tlv(payload).hex(" ").upper(),
                    "pages_from_4": format_pages(wrap_tlv(payload)),
                },
                indent=2,
            )
        )
        return 0
    if args.command == "export-flipper-url":
        return export_flipper_command(
            build_uri_record(args.url),
            args.tag_type,
            args.output,
            args.uid_seed,
        )
    if args.command == "build-campaign":
        manifest = build_campaign_bundle(args.config, args.out, args.flipper_root)
        print(json.dumps(manifest, indent=2))
        return 0

    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

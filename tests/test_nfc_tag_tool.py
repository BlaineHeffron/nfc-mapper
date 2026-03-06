import json
import tempfile
import unittest
from pathlib import Path

from tools.nfc_tag_tool import TAG_PROFILES
from tools.nfc_tag_tool import build_campaign_bundle
from tools.nfc_tag_tool import build_marketing_url
from tools.nfc_tag_tool import build_text_record
from tools.nfc_tag_tool import build_uri_record
from tools.nfc_tag_tool import extract_ndef_bytes
from tools.nfc_tag_tool import format_pages
from tools.nfc_tag_tool import parse_flipper_nfc
from tools.nfc_tag_tool import parse_ndef_message
from tools.nfc_tag_tool import render_flipper_nfc
from tools.nfc_tag_tool import wrap_tlv


class NfcTagToolTests(unittest.TestCase):
    def test_build_text_record_round_trip(self) -> None:
        record = build_text_record("hello world")
        parsed = parse_ndef_message(record)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].type_name, "T")
        self.assertEqual(parsed[0].decoded, "hello world")

    def test_build_url_record_round_trip(self) -> None:
        record = build_uri_record("https://example.com")
        parsed = parse_ndef_message(record)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].type_name, "U")
        self.assertEqual(parsed[0].decoded, "https://example.com")

    def test_extract_ndef_bytes_from_pages(self) -> None:
        message = build_text_record("tag")
        tlv = wrap_tlv(message)
        pages = {}
        for index, page in enumerate(format_pages(tlv), start=4):
            pages[index] = bytes.fromhex(page["bytes"])
        extracted = extract_ndef_bytes(pages)
        self.assertEqual(extracted, message)

    def test_render_flipper_dump_round_trip(self) -> None:
        profile = TAG_PROFILES["NTAG213"]
        content = render_flipper_nfc(build_uri_record("https://example.com/demo"), profile, "demo")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.nfc"
            path.write_text(content, encoding="utf-8")
            dump = parse_flipper_nfc(path)

        self.assertEqual(dump.metadata["Device type"], "NTAG/Ultralight")
        self.assertEqual(dump.metadata["NTAG/Ultralight type"], "NTAG213")
        self.assertEqual(len(dump.ndef_records), 1)
        self.assertEqual(dump.ndef_records[0].decoded, "https://example.com/demo")

    def test_build_marketing_url(self) -> None:
        url = build_marketing_url(
            base_url="https://example.com/offer?existing=1",
            campaign="spring_launch",
            source="nfc",
            medium="tag",
            content="white_round",
            term=None,
            extras={"ref": "booth_a", "variant": "blue"},
        )
        self.assertEqual(
            url,
            "https://example.com/offer?existing=1&utm_source=nfc&utm_medium=tag"
            "&utm_campaign=spring_launch&utm_content=white_round&ref=booth_a&variant=blue",
        )

    def test_build_campaign_bundle_outputs_site_and_flipper_files(self) -> None:
        config = {
            "campaign": {
                "name": "Spring Launch",
                "slug": "spring-launch",
                "base_url": "https://example.com/live",
                "default_tag_type": "NTAG213",
                "site": {
                    "title": "Spring Launch NFC",
                    "headline": "Tap into the launch",
                    "cta_label": "Keep me posted",
                },
            },
            "tags": [
                {
                    "name": "Booth A",
                    "slug": "booth-a",
                    "content": "booth_a",
                    "extras": {"ref": "booth_a"},
                    "interactive": {
                        "type": "reveal",
                        "headline": "Reveal the booth-only bonus",
                        "prompt": "One tap, one surprise.",
                        "outcomes": ["Sticker pack", "Demo slot"],
                    },
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "campaign.json"
            out_dir = Path(tmpdir) / "dist"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            manifest = build_campaign_bundle(config_path, out_dir)

            flipper_file = out_dir / "spring-launch" / "flipper_sd" / "ext" / "nfc" / "spring-launch" / "booth-a.nfc"
            site_file = out_dir / "spring-launch" / "site" / "index.html"
            site_data = out_dir / "spring-launch" / "site" / "campaign-data.json"

            self.assertTrue(flipper_file.exists())
            self.assertTrue(site_file.exists())
            self.assertTrue(site_data.exists())
            self.assertEqual(manifest["slug"], "spring-launch")
            self.assertEqual(manifest["tags"][0]["slug"], "booth-a")

            dump = parse_flipper_nfc(flipper_file)
            self.assertEqual(
                dump.ndef_records[0].decoded,
                "https://example.com/live?utm_source=nfc&utm_medium=tag"
                "&utm_campaign=spring-launch&utm_content=booth_a&ref=booth_a"
                "&tag=booth-a&experience=reveal",
            )


if __name__ == "__main__":
    unittest.main()

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

    def test_build_campaign_bundle_outputs_extended_assets(self) -> None:
        config = {
            "campaign": {
                "name": "Spring Launch",
                "slug": "spring-launch",
                "base_url": "https://example.com/live",
                "default_tag_type": "NTAG215",
                "redirect": {
                    "enabled": True,
                    "base_url": "https://go.example.com/t",
                    "mode": "path",
                    "code_length": 6,
                },
                "site": {
                    "title": "Spring Launch NFC",
                    "headline": "Tap into the launch",
                    "cta_label": "Keep me posted",
                    "integration": {
                        "provider": "airtable",
                        "endpoint": "/api/lead/airtable",
                    },
                },
            },
            "csv_import": {
                "path": "tags.csv",
                "defaults": {
                    "interactive": {
                        "type": "reveal",
                        "headline": "Reveal the booth-only bonus",
                        "prompt": "One tap, one surprise.",
                        "outcomes": ["Sticker pack", "Demo slot"],
                    }
                },
            },
        }

        csv_content = (
            "name,slug,content,extras,interactive_type,interactive_options,site_headline\n"
            "Booth A,booth-a,booth_a,ref=booth_a,quiz,Deck|Demo|Giveaway,Tap into Booth A\n"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "campaign.json"
            csv_path = Path(tmpdir) / "tags.csv"
            out_dir = Path(tmpdir) / "dist"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            csv_path.write_text(csv_content, encoding="utf-8")
            manifest = build_campaign_bundle(config_path, out_dir)

            bundle_dir = out_dir / "spring-launch"
            flipper_file = bundle_dir / "flipper_sd" / "ext" / "nfc" / "spring-launch" / "booth-a.nfc"
            site_data = bundle_dir / "site" / "campaign-data.json"
            qr_file = bundle_dir / "qr" / "booth-a.svg"
            print_sheet = bundle_dir / "print" / "deployment-sheet.html"
            redirect_map = bundle_dir / "redirects" / "redirect-map.json"
            manifest_csv = bundle_dir / "manifest.csv"
            hubspot_proxy = bundle_dir / "integrations" / "hubspot-proxy.js"
            airtable_proxy = bundle_dir / "integrations" / "airtable-proxy.js"
            redirect_handler = bundle_dir / "integrations" / "redirect-handler.js"

            self.assertTrue(flipper_file.exists())
            self.assertTrue(site_data.exists())
            self.assertTrue(qr_file.exists())
            self.assertTrue(print_sheet.exists())
            self.assertTrue(redirect_map.exists())
            self.assertTrue(manifest_csv.exists())
            self.assertTrue(hubspot_proxy.exists())
            self.assertTrue(airtable_proxy.exists())
            self.assertTrue(redirect_handler.exists())
            self.assertEqual(manifest["slug"], "spring-launch")
            self.assertEqual(manifest["tags"][0]["slug"], "booth-a")
            self.assertEqual(manifest["tags"][0]["redirect_target_url"], "https://example.com/live?utm_source=nfc&utm_medium=tag&utm_campaign=spring-launch&utm_content=booth_a&ref=booth_a&tag=booth-a&experience=quiz")
            self.assertTrue(manifest["tags"][0]["final_url"].startswith("https://go.example.com/t/"))

            dump = parse_flipper_nfc(flipper_file)
            self.assertEqual(dump.ndef_records[0].decoded, manifest["tags"][0]["final_url"])


if __name__ == "__main__":
    unittest.main()

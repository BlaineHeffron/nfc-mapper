# nfc-mapper

Tools for building Flipper Zero marketing-tag workflows with owned NFC stickers.

This repo is for benign use cases:

- inspect Flipper-exported `.nfc` files
- generate Flipper-compatible NTAG/Ultralight `.nfc` files for blank tags
- batch-build NFC campaign bundles from JSON
- generate a static landing page with tag-specific interactive content and lead capture

This repo does not include credential cloning, access-control bypass, or workflows meant to impersonate third-party tags.

## What It Builds

The main CLI is [tools/nfc_tag_tool.py](/home/blaine/projects/fzero/tools/nfc_tag_tool.py).

It can:

- inspect a saved Flipper `.nfc` dump and decode simple NDEF text/URL records
- build raw NDEF text and URL payloads
- generate Flipper-compatible `.nfc` files for `NTAG213`, `NTAG215`, and `NTAG216`
- build a full campaign bundle from JSON:
  - `flipper_sd/ext/nfc/<campaign>/...` for the Flipper SD card
  - `site/` static microsite assets
  - `manifest.json` mapping stickers to generated URLs and files

## Requirements

- Python 3.10+
- A Flipper Zero with NFC support
- Blank compatible tags
  - `NTAG215` is the safest default for marketing links
  - `NTAG213` is often too small once full HTTPS URLs and UTM params are added

## Quick Start

1. Edit [campaigns/example_marketing_campaign.json](/home/blaine/projects/fzero/campaigns/example_marketing_campaign.json).
2. Set `campaign.base_url` to the real hosted landing-page URL.
3. Update the campaign copy and define one entry in `tags[]` for each sticker.
4. Build the bundle:

```bash
python3 tools/nfc_tag_tool.py build-campaign campaigns/example_marketing_campaign.json --out dist
```

This creates:

- `dist/<campaign>/flipper_sd/ext/nfc/<campaign>/*.nfc`
- `dist/<campaign>/site/index.html`
- `dist/<campaign>/site/styles.css`
- `dist/<campaign>/site/app.js`
- `dist/<campaign>/site/campaign-data.json`
- `dist/<campaign>/manifest.json`

## Campaign Config

Start from [campaigns/example_marketing_campaign.json](/home/blaine/projects/fzero/campaigns/example_marketing_campaign.json).

Important fields:

- `campaign.name`: human-readable campaign name
- `campaign.slug`: folder-safe campaign identifier
- `campaign.base_url`: landing page URL the NFC stickers should open
- `campaign.default_tag_type`: use `NTAG215` unless you know your payload fits on `NTAG213`
- `campaign.default_source` and `campaign.default_medium`: defaults for generated UTM params
- `campaign.site.lead_endpoint`: optional JSON webhook endpoint for real lead capture
- `tags[]`: one entry per sticker

Useful per-tag fields:

- `name`
- `slug`
- `content`
- `extras`
- `interactive`
- `site_copy`
- `tag_type`

The builder appends UTM and routing params to each URL so the landing page can tell which sticker was tapped.

## Put It On The Flipper

Build the campaign first:

```bash
python3 tools/nfc_tag_tool.py build-campaign campaigns/example_marketing_campaign.json --out dist
```

Then copy the generated NFC files onto the Flipper SD card:

1. Mount the Flipper SD card on your computer.
2. Copy `dist/<campaign>/flipper_sd/ext/nfc/<campaign>/` to `/ext/nfc/<campaign>/` on the SD card.
3. Safely eject the SD card or disconnect the device.

You can also copy directly during the build if the SD card is mounted:

```bash
python3 tools/nfc_tag_tool.py build-campaign campaigns/example_marketing_campaign.json --out dist --flipper-root /path/to/flipper-sd-root
```

The tool writes to `/ext/nfc/<campaign>/` because that is the folder Flipper firmware uses for saved NFC files.

## Write A Tag With The Flipper

1. On the Flipper, open `NFC`.
2. Browse saved files.
3. Open one of the generated `.nfc` files.
4. Choose `Write`.
5. Hold a blank compatible sticker against the Flipper when prompted.
6. Test the result with a phone to confirm it opens the expected URL.

## Host The Landing Page

The generated microsite is static. Host `dist/<campaign>/site/` on any static host.

Before building for production:

- point `campaign.base_url` at the hosted microsite URL
- set `campaign.site.lead_endpoint` if you want submissions sent to a real webhook

If `lead_endpoint` is empty, the page stores leads in browser `localStorage` for demo/testing only.

## Common Commands

Inspect an existing Flipper NFC file:

```bash
python3 tools/nfc_tag_tool.py inspect path/to/tag.nfc
python3 tools/nfc_tag_tool.py inspect path/to/tag.nfc --json
```

Build raw NDEF payloads:

```bash
python3 tools/nfc_tag_tool.py build-text "tap for surprise"
python3 tools/nfc_tag_tool.py build-url "https://example.com"
python3 tools/nfc_tag_tool.py build-lead-url "https://example.com/demo" --campaign spring_launch --content white_round --extra ref=booth_a
```

Export a single Flipper-compatible NFC file:

```bash
python3 tools/nfc_tag_tool.py export-flipper-url "https://example.com/demo" dist/demo.nfc --tag-type NTAG215 --uid-seed booth-a
```

Run tests:

```bash
python3 -m unittest discover -s tests
```

## Practical Notes

- `NTAG215` is the practical default for longer marketing URLs.
- If a build fails because the payload is too large, shorten the URL, use a redirect domain, reduce query params, or move to a larger tag type.
- The generated sample campaign intentionally uses `example.com` placeholders and no real webhook.

## Public Repo Safety

This repository is intended to stay public-safe:

- no API keys
- no live webhook credentials
- no production customer data
- no private campaign endpoints committed by default

Before pushing changes, verify that:

- `campaign.base_url` does not expose a private staging hostname unless you intend to publish it
- `campaign.site.lead_endpoint` is blank or intentionally public
- generated `dist/` output is not committed unless you explicitly want sample artifacts in version control

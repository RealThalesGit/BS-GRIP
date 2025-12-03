#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# made with chatgpt ;) lol
import json
import os
import sys
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal

MAX_THREADS = 16
TIMEOUT = 30
FINGERPRINT_DIR = "BS-FINGERPRINTS"
ASSET_BASES = [
    "https://game-assets.brawlstarsgame.com/",
    "https://game-assets.tencent-cloud.com/"
]

STOP_FLAG = False
signal.signal(signal.SIGINT, lambda sig, frame: setattr(sys.modules[__name__], 'STOP_FLAG', True) or print("\n[!] Interrupted by user."))

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()

def log(msg):
    print(f"[+] {msg}")

def err(msg):
    print(f"[!] {msg}")

def normalize_assets(json_data):
    assets = []
    sha_base = json_data.get("sha")
    files_list = json_data.get("files") or json_data.get("assets") or []

    for a in files_list:
        sha = a.get("sha256", a.get("sha"))
        if "file" in a and sha:
            assets.append({
                "file": a["file"],
                "sha": sha
            })
    if not sha_base and assets:
        sha_base = assets[-1]["sha"]
    return assets, sha_base

def build_url(base, sha_base, file_path):
    return f"{base}{sha_base}/{file_path}"

def download_asset(asset, sha_base):
    file_path = asset["file"]
    expected_sha = asset["sha"]
    out_path = os.path.join(FINGERPRINT_DIR, sha_base, file_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    for base in ASSET_BASES:
        if STOP_FLAG:
            return False, f"{file_path}: Cancelled by user"
        url = build_url(base, sha_base, file_path)
        try:
            resp = requests.get(url, timeout=TIMEOUT, stream=True)
            if resp.status_code != 200:
                continue
            with open(out_path, "wb") as f:
                for chunk in resp.iter_content(65536):
                    if STOP_FLAG:
                        return False, f"{file_path}: Cancelled by user"
                    if chunk:
                        f.write(chunk)
            return True, f"{file_path} downloaded"
        except Exception:
            continue
    return False, f"{file_path}: Not found or download error"

def main(fingerprint_file):
    json_file = fingerprint_file if os.path.exists(fingerprint_file) else os.path.join(FINGERPRINT_DIR, fingerprint_file)
    if not os.path.exists(json_file):
        err(f"File '{fingerprint_file}' not found.")
        return

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assets, sha_base = normalize_assets(data)
    if not assets:
        err("No assets found in fingerprint.")
        return
    if not sha_base:
        err("Master SHA not found.")
        return

    log(f"Total assets: {len(assets)}")
    log(f"Master SHA: {sha_base}")

    success_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        futures = [pool.submit(download_asset, a, sha_base) for a in assets]

        for fut in as_completed(futures):
            if STOP_FLAG:
                break
            ok, msg = fut.result()
            if ok:
                success_count += 1
                log(f"[OK] {msg}")
            else:
                fail_count += 1
                err(f"[ERROR] {msg}")

    log(f"Download completed! {success_count} OK / {fail_count} ERROR(s)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python WOWIEGrip.py fingerprint.json")
        sys.exit(1)
    os.makedirs(FINGERPRINT_DIR, exist_ok=True)
    main(sys.argv[1])

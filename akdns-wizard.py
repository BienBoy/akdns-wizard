#!/usr/bin/env python3
"""
Interactive AKDNS rule and SmartDNS configuration wizard.

The wizard intentionally does not source akdns.sh.  It uses catalog.json as the
configuration source, scans check.sh for extra platform names, and invokes the
adapted check.sh JSON mode for unlock checks when available. Final output files
are written only after the user confirms the generated plan.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


VERSION = "1.0.0"
APP_NAME = "AKDNS Wizard"
CATALOG_FILE = "catalog.json"
CHECK_FILE = "check.sh"
_CHECK_BASH_CACHE: str | None | bool = False

# Fill this with the upstream catalog URL when it is available.  The script
# downloads the catalog into a temporary directory and does not persist it.
DEFAULT_CATALOG_URL = "https://raw.githubusercontent.com/BienBoy/akdns-wizard/refs/heads/main/catalog.json"
DEFAULT_CHECK_URL = "https://raw.githubusercontent.com/BienBoy/akdns-wizard/refs/heads/main/check.sh"
CATALOG_URL_ENV = "AKDNS_CATALOG_URL"
CHECK_URL_ENV = "AKDNS_CHECK_URL"
TEST_WORKERS_ENV = "AKDNS_TEST_WORKERS"
DEFAULT_TEST_TIMEOUT = 8.0
LOCKED_STRATEGY_STATUSES = {"no", "partial", "error"}

DEFAULT_OUTPUT_FILES = {
    "rules": "akdns-rules.json",
    "smartdns": "smartdns-akdns.conf",
}

# AKDNS unlock resolvers. Keep this list here so future IP changes are easy.
AKDNS_DNS_SERVERS = [
    "66.66.66.66",
    "45.207.157.146",
    "108.160.138.51",
    "139.180.133.239",
    "45.76.83.113",
    "45.76.71.83",
    "45.63.99.176",
    "166.0.199.207",
]

PUBLIC_DNS_PROFILES = {
    "cloudflare": {
        "zh": "Cloudflare",
        "en": "Cloudflare",
        "servers": ["1.1.1.1", "1.0.0.1"],
    },
    "google": {
        "zh": "Google",
        "en": "Google",
        "servers": ["8.8.8.8", "8.8.4.4"],
    },
    "quad9": {
        "zh": "Quad9",
        "en": "Quad9",
        "servers": ["9.9.9.9", "149.112.112.112"],
    },
    "adguard": {
        "zh": "AdGuard",
        "en": "AdGuard",
        "servers": ["94.140.14.14", "94.140.15.15"],
    },
    "custom": {
        "zh": "自定义公共 DNS",
        "en": "Custom public DNS",
        "servers": [],
    },
}

REGION_NAMES = {
    "HK": {"zh": "香港", "en": "Hong Kong"},
    "JP": {"zh": "日本", "en": "Japan"},
    "TW": {"zh": "台湾", "en": "Taiwan"},
    "SG": {"zh": "新加坡", "en": "Singapore"},
    "US": {"zh": "美国", "en": "United States"},
    "GB": {"zh": "英国", "en": "United Kingdom"},
    "UK": {"zh": "英国", "en": "United Kingdom"},
    "DE": {"zh": "德国", "en": "Germany"},
    "MO": {"zh": "澳门", "en": "Macau"},
    "KR": {"zh": "韩国", "en": "Korea"},
    "CA": {"zh": "加拿大", "en": "Canada"},
    "FR": {"zh": "法国", "en": "France"},
    "NL": {"zh": "荷兰", "en": "Netherlands"},
    "ES": {"zh": "西班牙", "en": "Spain"},
    "IT": {"zh": "意大利", "en": "Italy"},
    "CH": {"zh": "瑞士", "en": "Switzerland"},
    "DK": {"zh": "丹麦", "en": "Denmark"},
    "SE": {"zh": "瑞典", "en": "Sweden"},
    "NO": {"zh": "挪威", "en": "Norway"},
    "FI": {"zh": "芬兰", "en": "Finland"},
    "PT": {"zh": "葡萄牙", "en": "Portugal"},
    "RU": {"zh": "俄罗斯", "en": "Russia"},
    "UA": {"zh": "乌克兰", "en": "Ukraine"},
    "RO": {"zh": "罗马尼亚", "en": "Romania"},
    "ZA": {"zh": "南非", "en": "South Africa"},
    "AU": {"zh": "澳大利亚", "en": "Australia"},
    "NZ": {"zh": "新西兰", "en": "New Zealand"},
    "TH": {"zh": "泰国", "en": "Thailand"},
    "ID": {"zh": "印度尼西亚", "en": "Indonesia"},
    "VN": {"zh": "越南", "en": "Vietnam"},
    "MY": {"zh": "马来西亚", "en": "Malaysia"},
    "IN": {"zh": "印度", "en": "India"},
    "CN": {"zh": "中国大陆", "en": "China mainland"},
    "PH": {"zh": "菲律宾", "en": "Philippines"},
    "UNKNOWN": {"zh": "未知区域", "en": "Unknown region"},
    "GLOBAL": {"zh": "全球/多区域", "en": "Global/multi-region"},
}

REGION_ORDER = [
    "HK",
    "MO",
    "TW",
    "JP",
    "SG",
    "US",
    "KR",
    "GB",
    "DE",
    "FR",
    "NL",
    "ES",
    "IT",
    "CH",
    "DK",
    "SE",
    "NO",
    "FI",
    "PT",
    "RO",
    "RU",
    "UA",
    "CA",
    "AU",
    "NZ",
    "TH",
    "ID",
    "MY",
    "PH",
    "VN",
    "IN",
    "ZA",
    "GLOBAL",
    "UNKNOWN",
]

PRIMARY_TEST_REGIONS = ["HK", "TW", "MO", "JP", "US", "KR", "GLOBAL"]

TEST_REGION_GROUPS = [
    ("southeast-asia", {"zh": "东南亚", "en": "Southeast Asia"}, ["SG", "TH", "ID", "MY", "PH", "VN"]),
    ("europe", {"zh": "欧洲", "en": "Europe"}, ["GB", "DE", "FR", "NL", "ES", "IT", "CH", "DK", "SE", "NO", "FI", "PT", "RO", "RU", "UA"]),
    ("oceania", {"zh": "英联邦/大洋洲", "en": "Commonwealth/Oceania"}, ["CA", "AU", "NZ", "ZA"]),
    ("other", {"zh": "其他地区", "en": "Other regions"}, ["IN"]),
]

TEXT = {
    "zh": {
        "yes": "已解锁",
        "no": "未解锁",
        "unknown": "未知",
        "error": "检测失败",
        "partial": "部分可用",
        "catalog": "可生成规则",
        "check_only": "仅检测清单",
        "detector": "有原生检测",
        "no_detector": "无可靠检测",
        "region_all": "全部区域",
        "status_all": "全部状态",
        "selected": "已选择",
        "confirm_write": "确认写入这些文件？",
        "write_cancelled": "已取消写入；没有修改工作目录。",
        "write_skipped": "未保存文件；没有修改工作目录。",
    },
    "en": {
        "yes": "unlocked",
        "no": "locked",
        "unknown": "unknown",
        "error": "failed",
        "partial": "partial",
        "catalog": "configurable",
        "check_only": "check-list only",
        "detector": "unlock probe",
        "no_detector": "no reliable probe",
        "region_all": "All regions",
        "status_all": "All statuses",
        "selected": "selected",
        "confirm_write": "Write these files?",
        "write_cancelled": "Write cancelled; workspace was not modified.",
        "write_skipped": "Skipped saving; workspace was not modified.",
    },
}

CHECK_NAME_OVERRIDES = {
    "Steam": "Steam Store",
    "HBONow": "HBO Now",
    "BahamutAnime": "动画疯",
    "BilibiliHKMCTW": "Bilibili Hong Kong/Macau/Taiwan",
    "BilibiliTW": "Bilibili Taiwan",
    "BilibiliAnimeNew": "Bilibili Anime New",
    "BGlobalSEA": "Bilibili Global SouthEastAsia",
    "BGlobalTH": "Bilibili Global Thailand",
    "BGlobalID": "Bilibili Global Indonesia",
    "BGlobalVN": "Bilibili Global Vietnam",
    "AbemaTV_IPTest": "Abema TV",
    "PCRJP": "Princess Connect Re:Dive Japan",
    "UMAJP": "Pretty Derby Japan",
    "Kancolle": "Kancolle Japan",
    "KonosubaFD": "Konosuba Fantastic Days",
    "BBCiPLAYER": "BBC iPLAYER",
    "DisneyPlus": "Disney+",
    "DiscoveryPlus": "Discovery+",
    "HuluJP": "Hulu Japan",
    "MyTVSuper": "MyTVSuper",
    "NowE": "Now E",
    "ViuTV": "Viu.TV",
    "unext": "U-NEXT",
    "wowow": "WOWOW",
    "HBOMax": "HBO MAX",
    "Channel4": "Channel 4",
    "ITVHUB": "ITV Hub",
    "HuluUS": "Hulu US",
    "YouTube_Premium": "YouTube Premium",
    "YouTube_CDN": "YouTube CDN",
    "Youtube": "Youtube",
    "BritBox": "BritBox",
    "DMMTV": "DMM TV",
    "LiTV": "LiTV",
    "FuboTV": "Fubo TV",
    "TubiTV": "Tubi TV",
    "CoupangPlay": "Coupang Play",
    "LineTV.TW": "Line TV",
    "Viu.com": "Viu.com",
    "Niconico": "NicoNico",
    "ParamountPlus": "Paramount+",
    "FOD": "FOD(Fuji TV)",
    "PrimeVideo_Region": "Amazon Prime Video",
    "iQYI_Region": "iQyi Oversea",
    "HotStar": "HotStar",
    "Catchplay": "CatchPlay+",
    "Tiktok": "TikTok",
    "NHKPlus": "NHK+",
    "HoyTV": "HOY TV",
    "ProjectSekai": "Project Sekai: Colorful Stage",
    "DAM": "Karaoke@DAM",
    "J:COM_ON_DEMAND": "J:com On Demand",
    "RakutenMagazine": "Rakuten MAGAZINE",
    "mora": "Mora",
    "DAnimeStore": "D Anime Store",
    "RakutenTVJP": "Rakuten TV JP",
    "ofiii": "Ofiii",
    "Wikipedia_Editable": "Wikipedia",
    "Google": "Google Search",
    "Instagram.Music": "Instagram",
    "Copilot": "Microsoft Copilot",
    "Gemini_location": "Google AI",
}

SERVICE_NAME_ALIASES = {
    "Bilibili": "Bilibili 港澳台",
    "Bilibili Hong Kong/Macau/Taiwan": "Bilibili 港澳台",
}

CHECK_REGION_HINTS = {
    "BBC iPLAYER": ["GB"],
    "Bilibili Global SouthEastAsia": ["SG", "MY", "PH", "ID", "TH", "VN"],
    "Bilibili Global Thailand": ["TH"],
    "Bilibili Global Indonesia": ["ID"],
    "Bilibili Global Vietnam": ["VN"],
    "BritBox": ["GB", "US"],
    "Channel 4": ["GB"],
    "ITV Hub": ["GB"],
    "Hulu": ["US"],
    "Hulu US": ["US"],
    "HBO Now": ["US"],
    "Peacock TV": ["US"],
    "Sling TV": ["US"],
    "Pluto TV": ["US"],
    "FOX": ["US"],
    "ESPN+": ["US"],
    "ESPNPlus": ["US"],
    "Paramount+": ["US"],
    "Discovery+": ["US"],
    "Steam Store": ["GLOBAL"],
    "encore TVB": ["US"],
    "EPIX": ["US"],
    "Starz": ["US"],
    "Acorn TV": ["US", "GB"],
    "SHOWTIME": ["US"],
    "NBATV": ["US"],
    "ATTNOW": ["US"],
    "Cine Max": ["US"],
    "Direc TVGO": ["US"],
    "FXNOW": ["US"],
    "CWTV": ["US"],
    "Shudder": ["US"],
    "TLCGO": ["US"],
    "KBSAmerican": ["US"],
    "NBCTV": ["US"],
    "AETV": ["US"],
    "NFLPlus": ["US"],
    "Maths Spot": ["US"],
    "CBC Gem": ["CA"],
    "Crave": ["CA"],
    "Molotov": ["FR"],
    "Canal+": ["FR"],
    "Canal Plus": ["FR"],
    "France.tv": ["FR"],
    "Joyn": ["DE"],
    "Sky DE": ["DE"],
    "ZDF": ["DE"],
    "NLZIET": ["NL"],
    "videoland": ["NL"],
    "NPO Start Plus": ["NL"],
    "Rai Play": ["IT"],
    "Movistar+": ["ES"],
    "Movi Star Plus": ["ES"],
    "SKY CH": ["CH"],
    "Paravi": ["JP"],
    "Salto": ["FR"],
    "Rakuten TV": ["GLOBAL"],
    "HBO Spain": ["ES"],
    "HBO Nordic": ["NL", "DK", "SE", "NO", "FI"],
    "HBO Portugal": ["PT"],
    "Sky Go": ["GB"],
    "Discovery Plus UK": ["GB"],
    "Channel5": ["GB"],
    "Amediateka": ["RU"],
    "Megogo TV": ["UA"],
    "Stan": ["AU"],
    "Binge": ["AU"],
    "7plus": ["AU"],
    "Channel 9": ["AU"],
    "Channel 10": ["AU"],
    "ABC iView": ["AU"],
    "SBS on Demand": ["AU"],
    "Optus Sports": ["AU"],
    "Kayo Sports": ["AU"],
    "Docplay": ["AU"],
    "Neon TV": ["NZ"],
    "SkyGo NZ": ["NZ"],
    "ThreeNow": ["NZ"],
    "Maori TV": ["NZ"],
    "Wavve": ["KR"],
    "Tving": ["KR"],
    "Coupang Play": ["KR"],
    "Naver TV": ["KR"],
    "Afreeca TV": ["KR"],
    "Afreeca": ["KR"],
    "KBS Domestic": ["KR"],
    "KOCOWA": ["KR"],
    "PandaTV": ["KR"],
    "Spotv Now": ["KR"],
    "meWATCH": ["SG"],
    "Starhub TV+": ["SG"],
    "Starhub TVPlus": ["SG"],
    "AIS Play": ["TH"],
    "TrueID": ["TH"],
    "VTVcab": ["VN"],
    "Vidio": ["ID"],
    "MYTV": ["VN"],
    "ClipTV": ["VN"],
    "GalaxyPlay": ["VN"],
    "K+": ["VN"],
    "KPlus": ["VN"],
    "TV360": ["VN"],
    "Sooka": ["MY"],
    "MXPlayer": ["IN"],
    "TataPlay": ["IN"],
    "SonyLiv": ["IN"],
    "JioCinema": ["IN"],
    "Zee5": ["IN"],
    "HBOGO ASIA": ["HK", "SG", "TH", "ID", "MY", "PH"],
    "Setanta Sports": ["GLOBAL"],
    "Mola TV": ["ID"],
    "Bein Connect": ["GLOBAL"],
    "Eurosport RO": ["RO"],
    "Popcornflix": ["US"],
    "Philo": ["US"],
    "Crunchyroll": ["US"],
    "Crackle": ["US"],
    "Sky Show Time": ["GB", "DE", "FR", "ES", "IT", "NL"],
    "Eurosport": ["GB", "DE", "FR", "ES", "IT", "NL"],
    "Viaplay": ["NL", "DK", "SE", "NO", "FI"],
    "DStv": ["ZA"],
    "be IN Sports": ["GLOBAL"],
    "Bilibili Anime New": ["HK", "MO", "TW"],
    "YouTube Premium": ["GLOBAL"],
    "YouTube CDN": ["GLOBAL"],
    "Netflix CDN": ["GLOBAL"],
    "LiTV": ["TW"],
    "DMM TV": ["JP"],
    "Fubo TV": ["US"],
    "Tubi TV": ["US"],
}

SERVICE_REGION_HINTS = {
    "Netflix": ["GLOBAL"],
    "Disney+": ["GLOBAL"],
    "Spotify": ["GLOBAL"],
    "Dazn": ["GLOBAL"],
    "TikTok": ["GLOBAL"],
    "Reddit": ["GLOBAL"],
    "Wikipedia": ["GLOBAL"],
    "Amazon Prime Video": ["GLOBAL"],
    "Paramount+": ["GLOBAL"],
    "Discovery+": ["GLOBAL"],
    "HBO MAX": ["US"],
    "ChatGPT": ["GLOBAL"],
    "Sora": ["GLOBAL"],
    "Claude": ["GLOBAL"],
    "Google AI": ["GLOBAL"],
    "Google Search": ["GLOBAL"],
    "Youtube": ["GLOBAL"],
    "Google Play": ["GLOBAL"],
    "Apple AI": ["GLOBAL"],
    "Meta AI": ["GLOBAL"],
    "Microsoft Copilot": ["GLOBAL"],
    "Instagram": ["GLOBAL"],
    "动画疯": ["HK", "TW"],
    "Bilibili 港澳台": ["HK", "MO", "TW"],
    "Bilibili": ["HK", "MO", "TW"],
    "Bilibili Hong Kong/Macau/Taiwan": ["HK", "MO", "TW"],
    "Bilibili Taiwan": ["TW"],
    "KKTV": ["TW"],
    "Line TV": ["TW"],
    "Hami Video": ["TW"],
    "CatchPlay+": ["TW"],
    "Friday Video": ["TW"],
    "4GTV": ["TW"],
    "MyVideo": ["TW"],
    "Abema TV": ["JP"],
    "DMM": ["JP"],
    "Hulu Japan": ["JP"],
    "NicoNico": ["JP"],
    "NHK+": ["JP"],
    "U-NEXT": ["JP"],
    "TVer": ["JP"],
    "D Anime Store": ["JP"],
    "J:com On Demand": ["JP"],
    "Pretty Derby Japan": ["JP"],
    "VideoMarket": ["JP"],
    "FOD(Fuji TV)": ["JP"],
    "Radiko": ["JP"],
    "Karaoke@DAM": ["JP"],
    "Lemino": ["JP"],
    "MGStage": ["JP"],
    "AnimeFesta": ["JP"],
    "Telasa": ["JP"],
    "WOWOW": ["JP"],
    "Rakuten TV JP": ["JP"],
    "Princess Connect Re:Dive Japan": ["JP"],
    "Project Sekai: Colorful Stage": ["JP"],
    "Konosuba Fantastic Days": ["JP"],
    "Rakuten MAGAZINE": ["JP"],
    "Mora": ["JP"],
    "music.jp": ["JP"],
    "EroGameSpace": ["JP"],
    "Kancolle Japan": ["JP"],
    "MyTVSuper": ["HK"],
    "Viu.TV": ["HK"],
    "Now E": ["HK"],
    "TVBAnywhere+": ["HK"],
    "HOY TV": ["HK"],
    "Ofiii": ["HK"],
    "Viu.com": ["HK", "SG", "TH", "ID", "MY", "PH"],
    "iQyi Oversea": ["GLOBAL"],
    "HotStar": ["IN", "ID", "MY", "TH"],
    "WATCHA": ["KR"],
    "SD Gundam G Generation Eternal": ["JP"],
}

UA_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
UA_DALVIK = "Dalvik/2.1.0 (Linux; U; Android 9; Pixel Build/PQ3A)"


@dataclass
class Backend:
    name: str
    geocode: str


@dataclass
class ProbeResult:
    status: str
    region: str | None = None
    detail: str = ""
    error: str = ""


@dataclass
class Service:
    name: str
    domains: list[str] = field(default_factory=list)
    blocked_backends: set[str] = field(default_factory=set)
    source_catalog: bool = False
    source_check: bool = False
    check_function: str | None = None
    region_hints: list[str] = field(default_factory=list)
    selected: bool = False
    selected_backend: str | None = None
    probe_result: ProbeResult = field(default_factory=lambda: ProbeResult("unknown"))

    @property
    def configurable(self) -> bool:
        return self.source_catalog and bool(self.domains)


@dataclass
class WizardState:
    lang: str
    services: list[Service]
    backends: dict[str, Backend]
    test_regions: set[str] = field(default_factory=set)
    tested_services: set[str] = field(default_factory=set)
    backend_preferred_name: str = ""
    dns_profile: str = "cloudflare"
    public_dns_servers: list[str] = field(default_factory=lambda: list(PUBLIC_DNS_PROFILES["cloudflare"]["servers"]))
    akdns_servers: list[str] = field(default_factory=lambda: list(AKDNS_DNS_SERVERS))
    mode: str = "test-and-generate"
    temp_dir: Path | None = None
    check_path: Path | None = None
    output_paths: dict[str, Path] = field(default_factory=dict)


@dataclass(frozen=True)
class WizardResult:
    wrote_files: bool = False
    displayed_only: bool = False


@dataclass(frozen=True)
class BackendStrategyResult:
    matched: int = 0
    changed: int = 0
    skipped: int = 0


class BackRequested(Exception):
    pass


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def canonical_service_name(name: str) -> str:
    return SERVICE_NAME_ALIASES.get(name, name)


def char_display_cell_width(char: str) -> int:
    if unicodedata.combining(char):
        return 0
    return 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1


def display_cell_width(value: str) -> int:
    return sum(char_display_cell_width(char) for char in value)


def fit_display_cells(value: str, width: int, *, pad: bool = False) -> str:
    if width <= 0:
        return ""
    used = 0
    chars = []
    for char in value:
        char_width = char_display_cell_width(char)
        if used + char_width > width:
            break
        chars.append(char)
        used += char_width
    if pad and used < width:
        chars.append(" " * (width - used))
    return "".join(chars)


def pad_display_cells(value: str, width: int) -> str:
    value = fit_display_cells(value, width)
    return value + (" " * max(0, width - display_cell_width(value)))


def ellipsize_display_cells(value: str, width: int) -> str:
    if display_cell_width(value) <= width:
        return value
    if width <= 3:
        return fit_display_cells(value, width)
    return fit_display_cells(value, width - 3) + "..."


def pad_or_ellipsize_display_cells(value: str, width: int) -> str:
    value = ellipsize_display_cells(value, width)
    return value + (" " * max(0, width - display_cell_width(value)))


def format_columns(columns: Iterable[tuple[object, int]], gap: str = "  ") -> str:
    return gap.join(pad_or_ellipsize_display_cells(str(value), width) for value, width in columns)


def display_cell_clusters(value: str) -> Iterable[tuple[str, int]]:
    cluster = ""
    cluster_width = 0
    for char in value:
        char_width = char_display_cell_width(char)
        if char_width == 0 and cluster:
            cluster += char
            continue
        if cluster:
            yield cluster, cluster_width
        cluster = char
        cluster_width = char_width
    if cluster:
        yield cluster, cluster_width


def fill_curses_row(window, row: int, width: int, attr: int) -> None:  # type: ignore[no-untyped-def]
    """Fill one row cell-by-cell to avoid backend-specific hline/wrap artifacts."""
    limit = max(0, width - 1)
    for col in range(limit):
        with contextlib.suppress(Exception):
            window.addch(row, col, " ", attr)
    with contextlib.suppress(Exception):
        window.touchline(row, 1)


def region_name(code: str | None, lang: str) -> str:
    if not code:
        code = "UNKNOWN"
    code = code.upper()
    if code == "UK":
        code = "GB"
    return REGION_NAMES.get(code, {"zh": code, "en": code}).get(lang, code)


def format_region_list(regions: Iterable[str], lang: str, limit: int | None = None) -> str:
    region_list = list(regions)
    normalized = [normalize_region_input(code) for code in region_list]
    visible = normalized if limit is None else normalized[:limit]
    values = [region_name(code, lang) for code in visible]
    if limit is not None and len(normalized) > limit:
        values.append(f"+{len(normalized) - limit}")
    return ",".join(values) or "-"


def format_backend(backend: Backend | None, lang: str) -> str:
    if backend is None:
        return "-"
    name = backend.name
    geocode = backend.geocode.upper()
    if normalize_name(name) == normalize_name(geocode):
        return region_name(geocode, lang)
    localized = region_name(geocode, lang)
    if normalize_name(name) == normalize_name(localized):
        return name
    return f"{name} ({localized})"


def detect_language() -> str:
    lang = (
        os.environ.get("AKDNS_LANG")
        or os.environ.get("LANG")
        or os.environ.get("LC_ALL")
        or os.environ.get("LC_MESSAGES")
        or ""
    ).lower()
    return "zh" if lang.startswith("zh") else "en"


def load_catalog(path: Path) -> tuple[dict[str, Backend], OrderedDict[str, Service]]:
    with path.open("r", encoding="utf-8") as f:
        catalog = json.load(f)
    backends = {
        item["name"]: Backend(name=item["name"], geocode=item.get("geocode", item["name"]))
        for item in catalog.get("backends", [])
    }
    services: OrderedDict[str, Service] = OrderedDict()
    for item in catalog.get("services", []):
        name = canonical_service_name(item["name"])
        service = Service(
            name=name,
            domains=dedupe(item.get("domains", [])),
            blocked_backends=set(item.get("blockedBackends", [])),
            source_catalog=True,
        )
        services[normalize_name(name)] = service
    return backends, services


def dedupe(items: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        item = str(item).strip()
        key = item.lower()
        if item and key not in seen:
            result.append(item)
            seen.add(key)
    return result


def scan_check_services(path: Path) -> list[tuple[str, str]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    result = []
    pattern = re.compile(r"^function\s+([A-Za-z0-9_.:+-]+)\s*\(\)", re.MULTILINE)
    for match in pattern.finditer(text):
        func = match.group(1)
        raw = None
        for prefix in ("MediaUnlockTest_", "MediaUnblockTest_", "AIUnlockTest_", "GameTest_"):
            if func.startswith(prefix):
                raw = func[len(prefix) :]
                break
        if raw is None:
            continue
        result.append((canonical_service_name(CHECK_NAME_OVERRIDES.get(raw, prettify_check_name(raw))), func))
    return result


def prettify_check_name(raw: str) -> str:
    value = raw.replace("_Region", "").replace("_", " ").replace(".", " ")
    value = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value or raw


def service_region_hints(name: str) -> list[str]:
    hints = SERVICE_REGION_HINTS.get(name) or CHECK_REGION_HINTS.get(name)
    if hints is None:
        key = normalize_name(name)
        for table in (SERVICE_REGION_HINTS, CHECK_REGION_HINTS):
            for known_name, known_hints in table.items():
                if normalize_name(known_name) == key:
                    hints = known_hints
                    break
            if hints is not None:
                break
    return list(hints or ["UNKNOWN"])


def merge_check_services(services: OrderedDict[str, Service], check_items: list[tuple[str, str]]) -> None:
    for name, func in check_items:
        key = normalize_name(name)
        if key in services:
            services[key].source_check = True
            services[key].check_function = func
            if not services[key].region_hints:
                services[key].region_hints = service_region_hints(name)
            continue
        service = Service(
            name=name,
            source_check=True,
            check_function=func,
            region_hints=service_region_hints(name),
        )
        services[key] = service


def candidate_backends(service: Service, backends: dict[str, Backend]) -> list[Backend]:
    if not service.source_catalog:
        return []
    return [
        backend
        for name, backend in backends.items()
        if name not in service.blocked_backends
    ]


def backend_region(backend: Backend) -> str:
    return normalize_region_input(backend.geocode)


def backend_regions(backends: Iterable[Backend]) -> list[str]:
    return sorted({backend_region(backend) for backend in backends})


def service_backend_regions(service: Service, backends: dict[str, Backend]) -> set[str]:
    return set(backend_regions(candidate_backends(service, backends)))


def choose_backend_by_name(service: Service, backends: dict[str, Backend], backend_name: str) -> str | None:
    if not backend_name:
        return None
    normalized = normalize_name(backend_name)
    for backend in candidate_backends(service, backends):
        if normalize_name(backend.name) == normalized:
            return backend.name
    return None


def choose_first_backend(service: Service, backends: dict[str, Backend]) -> str | None:
    candidates = candidate_backends(service, backends)
    return candidates[0].name if candidates else None


def choose_default_backend(service: Service, backends: dict[str, Backend], preferred_backend: str) -> str | None:
    return choose_backend_by_name(service, backends, preferred_backend) or choose_first_backend(service, backends)


def candidate_regions(service: Service, backends: dict[str, Backend]) -> list[str]:
    regions = []
    for backend in candidate_backends(service, backends):
        code = backend.geocode.upper()
        if code == "UK":
            code = "GB"
        if code not in regions:
            regions.append(code)
    if not regions and service.source_catalog:
        regions.append("UNKNOWN")
    return regions


def apply_backend_strategy(
    services: Iterable[Service],
    backends: dict[str, Backend],
    preferred_backend: str,
    *,
    status_filter: set[str] | None = None,
    fallback_first: bool = False,
    only_unselected: bool = False,
) -> BackendStrategyResult:
    matched = 0
    changed = 0
    skipped = 0
    for service in services:
        if not service_matches_strategy_scope(service, status_filter, only_unselected):
            continue
        matched += 1
        backend = choose_backend_by_name(service, backends, preferred_backend)
        if backend is None and fallback_first:
            backend = choose_first_backend(service, backends)
        if backend is None:
            skipped += 1
            continue
        service.selected = True
        service.selected_backend = backend
        changed += 1
    return BackendStrategyResult(matched=matched, changed=changed, skipped=skipped)


def service_matches_strategy_scope(service: Service, status_filter: set[str] | None, only_unselected: bool) -> bool:
    if not service.configurable:
        return False
    if status_filter is not None and service.probe_result.status not in status_filter:
        return False
    return not (only_unselected and service.selected)


def count_strategy_scope(services: Iterable[Service], status_filter: set[str] | None, only_unselected: bool) -> int:
    return sum(1 for service in services if service_matches_strategy_scope(service, status_filter, only_unselected))


def clear_strategy_services(services: Iterable[Service], status_filter: set[str] | None, only_unselected: bool) -> BackendStrategyResult:
    matched = 0
    changed = 0
    for service in services:
        if not service_matches_strategy_scope(service, status_filter, only_unselected):
            continue
        matched += 1
        if service.selected or service.selected_backend:
            changed += 1
        service.selected = False
        service.selected_backend = None
    return BackendStrategyResult(matched=matched, changed=changed)


def strategy_result_text(result: BackendStrategyResult, lang: str) -> str:
    if lang == "zh":
        return f"已应用策略：匹配 {result.matched} 个平台，选择/更新 {result.changed} 个，跳过 {result.skipped} 个不可用项。"
    return f"Strategy applied: matched {result.matched} services, selected/updated {result.changed}, skipped {result.skipped} unavailable items."


def filter_summary_text(
    lang: str,
    search: str,
    status_filter: str,
    service_region_filter: str,
    region_filter: str,
    selected_count: int,
    visible_count: int | None = None,
) -> str:
    status = TEXT[lang]["status_all"] if status_filter == "all" else status_label(status_filter, lang)
    service_region = TEXT[lang]["region_all"] if service_region_filter == "all" else region_name(service_region_filter, lang)
    region = TEXT[lang]["region_all"] if region_filter == "all" else region_name(region_filter, lang)
    if lang == "zh":
        suffix = f"  可见 {visible_count}" if visible_count is not None else ""
        return f"过滤: status={status} 服务区域={service_region} backend地区={region} search={search or '-'}{suffix}  已选择 {selected_count}"
    suffix = f"  visible {visible_count}" if visible_count is not None else ""
    return f"Filter: status={status} service-region={service_region} backend-region={region} search={search or '-'}{suffix}  selected {selected_count}"


def filter_services(
    services: Iterable[Service],
    backends: dict[str, Backend],
    search: str,
    status_filter: str,
    service_region_filter: str,
    region_filter: str,
) -> list[Service]:
    result = []
    lowered_search = search.lower()
    for service in services:
        if not service.configurable:
            continue
        haystack = " ".join([service.name, " ".join(service.domains), " ".join(service.region_hints)]).lower()
        if lowered_search and lowered_search not in haystack:
            continue
        if status_filter != "all" and service.probe_result.status != status_filter:
            continue
        if service_region_filter != "all" and service_region_filter not in service.region_hints:
            continue
        if region_filter != "all" and region_filter not in service_backend_regions(service, backends):
            continue
        result.append(service)
    return sorted(result, key=lambda item: (status_score(item), item.name.lower()))


def strategy_scope_options(all_services: list[Service], visible: list[Service]) -> list[tuple[str, list[Service], set[str] | None, bool]]:
    return [
        ("visible-locked", visible, LOCKED_STRATEGY_STATUSES, False),
        ("visible-remaining", visible, LOCKED_STRATEGY_STATUSES, True),
        ("visible-all", visible, None, False),
        ("selected", selected_services_from(all_services), None, False),
        ("all-locked", all_services, LOCKED_STRATEGY_STATUSES, False),
        ("all-remaining", all_services, LOCKED_STRATEGY_STATUSES, True),
    ]


def selected_services_from(services: Iterable[Service]) -> list[Service]:
    return [service for service in services if service.selected and service.selected_backend]


def strategy_scope_label(label: str, lang: str) -> str:
    zh = {
        "visible-locked": "当前筛选中的未解锁/部分可用/检测失败",
        "visible-remaining": "当前筛选中还未选择的未解锁/检测失败",
        "visible-all": "当前筛选全部平台",
        "selected": "已选择的平台",
        "all-locked": "全部未解锁/部分可用/检测失败",
        "all-remaining": "全部还未选择的未解锁/检测失败",
    }
    en = {
        "visible-locked": "Locked/partial/failed in current filter",
        "visible-remaining": "Unselected locked/failed in current filter",
        "visible-all": "All services in current filter",
        "selected": "Already selected services",
        "all-locked": "All locked/partial/failed services",
        "all-remaining": "All unselected locked/failed services",
    }
    return (zh if lang == "zh" else en).get(label, label)


def build_services(root: Path, catalog_path: Path, check_path: Path | None = None) -> tuple[dict[str, Backend], list[Service]]:
    backends, services = load_catalog(catalog_path)
    merge_check_services(services, scan_check_services(check_path or root / CHECK_FILE))
    for service in services.values():
        if not service.region_hints:
            service.region_hints = service_region_hints(service.name)
    return backends, list(services.values())


def fetch_text_file(url: str, fallback_path: Path, temp_dir: Path, file_name: str, env_name: str) -> Path:
    env_value = os.environ.get(env_name, "").strip()
    source_url = env_value or url
    if source_url:
        target = temp_dir / file_name
        req = urllib.request.Request(source_url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                target.write_bytes(resp.read())
            return target
        except Exception:
            if fallback_path.exists():
                print(f"Warning: failed to fetch {file_name}; using local {fallback_path}", file=sys.stderr)
                return fallback_path
            raise
    if fallback_path.exists():
        return fallback_path
    raise FileNotFoundError(f"{file_name} URL is empty and local {fallback_path} does not exist")


def fetch_catalog(catalog_url: str, fallback_path: Path, temp_dir: Path) -> Path:
    return fetch_text_file(catalog_url, fallback_path, temp_dir, CATALOG_FILE, CATALOG_URL_ENV)


def fetch_check_script(check_url: str, fallback_path: Path, temp_dir: Path) -> Path | None:
    try:
        return fetch_text_file(check_url, fallback_path, temp_dir, CHECK_FILE, CHECK_URL_ENV)
    except FileNotFoundError:
        return None


class HTTPClient:
    def __init__(self, timeout: float, ip_version: str = "auto") -> None:
        self.timeout = timeout
        self.ip_version = ip_version

    def request(
        self,
        url: str,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> tuple[int, str, str]:
        headers = {"User-Agent": UA_BROWSER, **(headers or {})}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        opener_handlers = [urllib.request.HTTPSHandler(context=_ssl_context())]
        if not follow_redirects:
            opener_handlers.append(NoRedirectHandler)
        opener = urllib.request.build_opener(*opener_handlers)
        with force_ip_version(self.ip_version):
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read(2_000_000).decode("utf-8", errors="ignore")
                    return resp.getcode(), resp.geturl(), body
            except urllib.error.HTTPError as exc:
                body = exc.read(2_000_000).decode("utf-8", errors="ignore")
                return exc.code, exc.geturl(), body

    def head_or_get(self, url: str) -> tuple[int, str, str]:
        try:
            return self.request(url, method="HEAD")
        except Exception:
            return self.request(url, method="GET")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    return context


@contextlib.contextmanager
def force_ip_version(ip_version: str):
    if ip_version not in {"4", "6"}:
        yield
        return

    original = socket.getaddrinfo
    family = socket.AF_INET if ip_version == "4" else socket.AF_INET6

    def filtered_getaddrinfo(*args, **kwargs):  # type: ignore[no-untyped-def]
        results = original(*args, **kwargs)
        filtered = [item for item in results if item[0] == family]
        return filtered or results

    socket.getaddrinfo = filtered_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original  # type: ignore[assignment]


def probe_unknown(client: HTTPClient) -> ProbeResult:
    return ProbeResult("unknown", detail="no reliable native probe")


def probe_url_status(
    client: HTTPClient,
    url: str,
    ok_codes: set[int],
    no_codes: set[int],
    detail: str = "",
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> ProbeResult:
    try:
        code, final_url, body = client.request(url, method=method, data=data, headers=headers)
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if code in ok_codes:
        return ProbeResult("yes", detail=detail or f"HTTP {code}")
    if code in no_codes:
        return ProbeResult("no", detail=detail or f"HTTP {code}")
    return ProbeResult("unknown", detail=f"HTTP {code} {final_url}")


def json_from(body: str) -> dict:
    try:
        data = json.loads(body)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def json_path(data: object, *keys: str) -> object:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def source_contains(source: str, markers: Iterable[str]) -> bool:
    lowered = source.lower()
    return any(marker.lower() in lowered for marker in markers)


def probe_markers(
    client: HTTPClient,
    url: str,
    yes_markers: Iterable[str] = (),
    no_markers: Iterable[str] = (),
    yes_codes: set[int] | None = None,
    no_codes: set[int] | None = None,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> ProbeResult:
    try:
        code, final_url, body = client.request(url, method=method, data=data, headers=headers)
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    source = f"{final_url}\n{body}"
    if no_codes and code in no_codes:
        return ProbeResult("no", detail=f"HTTP {code}")
    if source_contains(source, no_markers):
        return ProbeResult("no", detail=f"HTTP {code}")
    if yes_codes and code in yes_codes:
        return ProbeResult("yes", detail=f"HTTP {code}")
    if source_contains(source, yes_markers):
        return ProbeResult("yes", detail=f"HTTP {code}")
    return ProbeResult("unknown", detail=f"HTTP {code} {final_url}")


def probe_json_code(
    client: HTTPClient,
    url: str,
    path: tuple[str, ...],
    yes_values: set[str],
    no_values: set[str],
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    region: str | None = None,
) -> ProbeResult:
    try:
        _, _, body = client.request(url, method=method, data=data, headers=headers)
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    value = json_path(json_from(body), *path)
    value_text = str(value)
    if value_text in yes_values:
        return ProbeResult("yes", region=region, detail=f"{'.'.join(path)}={value_text}")
    if value_text in no_values:
        return ProbeResult("no", region=region, detail=f"{'.'.join(path)}={value_text}")
    return ProbeResult("unknown", region=region, detail=f"{'.'.join(path)}={value_text}")


def probe_abema(client: HTTPClient) -> ProbeResult:
    try:
        code, _, body = client.request(
            "https://api.abema.io/v1/ip/check?device=android",
            headers={"User-Agent": UA_DALVIK},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if code >= 500:
        return ProbeResult("unknown", detail=f"HTTP {code}")
    region = json_from(body).get("isoCountryCode")
    if region == "JP":
        return ProbeResult("yes", region=region)
    if region:
        return ProbeResult("no", region=region, detail="overseas only")
    return ProbeResult("unknown", detail="missing region")


def probe_netflix(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body1 = client.request("https://www.netflix.com/title/81280792")
        _, _, body2 = client.request("https://www.netflix.com/title/70143836")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    body = body1 + body2
    region_match = re.search(r'"requestCountry"\s*:\s*\{[^}]*"id"\s*:\s*"([A-Z]{2})"', body)
    region = region_match.group(1) if region_match else None
    if "og:video" in body:
        return ProbeResult("yes", region=region)
    if "netflix.reactContext" in body or "requestCountry" in body:
        return ProbeResult("partial", region=region, detail="Originals only")
    return ProbeResult("unknown", region=region)


def probe_dazn(client: HTTPClient) -> ProbeResult:
    payload = {
        "LandingPageKey": "generic",
        "Languages": "zh-CN,zh,en",
        "Platform": "web",
        "PlatformAttributes": {},
        "Manufacturer": "",
        "PromoCode": "",
        "Version": "2",
    }
    try:
        _, _, body = client.request(
            "https://startup.core.indazn.com/misl/v5/Startup",
            method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "Security policy has been breached" in body or "Forbidden" in body:
        return ProbeResult("no", detail="banned")
    data = json_from(body)
    region = ((data.get("Region") or {}).get("GeolocatedCountry") or "").upper() or None
    allowed = (data.get("Region") or {}).get("isAllowed")
    if allowed is True:
        return ProbeResult("yes", region=region)
    if allowed is False:
        return ProbeResult("no", region=region)
    return ProbeResult("unknown", region=region)


def probe_mytvsuper(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://www.mytvsuper.com/api/auth/getSession/self/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region = str(json_from(body).get("region", ""))
    if region == "1":
        return ProbeResult("yes", region="HK")
    if region:
        return ProbeResult("no", detail=f"region={region}")
    return ProbeResult("unknown")


def probe_viutv(client: HTTPClient) -> ProbeResult:
    payload = {
        "callerReferenceNo": "20210726112323",
        "contentId": "099",
        "contentType": "Channel",
        "channelno": "099",
        "mode": "prod",
        "deviceId": "29b3cb117a635d5b56",
        "deviceType": "ANDROID_WEB",
    }
    try:
        _, _, body = client.request(
            "https://api.viu.now.com/p8/3/getLiveURL",
            method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    response = json_from(body).get("responseCode")
    if response == "SUCCESS":
        return ProbeResult("yes", region="HK")
    if response == "GEO_CHECK_FAIL":
        return ProbeResult("no")
    return ProbeResult("unknown", detail=str(response or "missing responseCode"))


def probe_viu_com(client: HTTPClient) -> ProbeResult:
    try:
        _, final_url, _ = client.request("https://www.viu.com/")
        _, _, ban_body = client.request("https://d3o7oi00quuwqu.cloudfront.net")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    parts = urllib.parse.urlparse(final_url).path.strip("/").split("/")
    region = parts[0].upper() if parts and parts[0] else None
    if region == "NO-SERVICE":
        return ProbeResult("no")
    if "block access" in ban_body.lower():
        return ProbeResult("no", region=region)
    return ProbeResult("yes", region=region)


def probe_kktv(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://api.kktv.me/v3/ipcheck")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region = json_from(body).get("country")
    if region == "TW":
        return ProbeResult("yes", region=region)
    if region:
        return ProbeResult("no", region=region)
    return ProbeResult("unknown")


def probe_linetv(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request(
            "https://www.linetv.tw/api/part/11829/eps/1/part?chocomemberId=&appId=062097f1b1f34e11e7f82aag22000aee"
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    country = json_from(body).get("countryCode")
    if country == 228:
        return ProbeResult("yes", region="TW")
    if country is not None:
        return ProbeResult("no", detail=f"countryCode={country}")
    return ProbeResult("unknown")


def probe_hami(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://hamivideo.hinet.net/api/play.do?id=OTT_VOD_0000249064&freeProduct=1")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    code = json_from(body).get("code")
    if code == "06001-107":
        return ProbeResult("yes", region="TW")
    if code == "06001-106":
        return ProbeResult("no")
    return ProbeResult("unknown", detail=str(code or "missing code"))


def probe_4gtv(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request(
            "https://api2.4gtv.tv//Vod/GetVodUrl3",
            method="POST",
            data=b"value=D33jXJ0JVFkBqV%2BZSi1mhPltbejAbPYbDnyI9hmfqjKaQwRQdj7ZKZRAdb16%2FRUrE8vGXLFfNKBLKJv%2BfDSiD%2BZJlUa5Msps2P4IWuTrUP1%2BCnS255YfRadf%2BKLUhIPj",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    success = json_from(body).get("Success")
    if success is True:
        return ProbeResult("yes", region="TW")
    if success is False:
        return ProbeResult("no")
    return ProbeResult("unknown")


def probe_catchplay(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request(
            "https://sunapi.catchplay.com/geo",
            headers={"authorization": "Basic NTQ3MzM0NDgtYTU3Yi00MjU2LWE4MTEtMzdlYzNkNjJmM2E0Ok90QzR3elJRR2hLQ01sSDc2VEoy"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    data = json_from(body)
    code = data.get("code")
    region = ((data.get("data") or {}).get("isoCode") or data.get("isoCode") or None)
    if code == "0" or code == 0:
        return ProbeResult("yes", region=region)
    if str(code) == "100016":
        return ProbeResult("no", region=region)
    return ProbeResult("unknown", region=region, detail=f"code={code}")


def probe_friday(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request(
            "https://video.friday.tw/api2/streaming/get?streamingId=122581&streamingType=2&contentType=4&contentId=1&clientId="
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    code = str(json_from(body).get("code", ""))
    if code == "0000":
        return ProbeResult("yes", region="TW")
    if code == "1006":
        return ProbeResult("no")
    return ProbeResult("unknown", detail=f"code={code or 'missing'}")


def probe_niconico(client: HTTPClient) -> ProbeResult:
    return probe_url_status(
        client,
        "https://www.nicovideo.jp/watch/so23017073",
        ok_codes={200},
        no_codes={400, 403},
    )


def probe_mgstage(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://www.mgstage.com/", ok_codes={200}, no_codes={403})


def probe_fod(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://geocontrol1.stream.ne.jp/fod-geo/check.xml?time=1624504256")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "true" in body.lower():
        return ProbeResult("yes", region="JP")
    if "false" in body.lower():
        return ProbeResult("no")
    return ProbeResult("unknown")


def probe_radiko(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://radiko.jp/area?_=1625406539531")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if 'class="OUT"' in body:
        return ProbeResult("no")
    if "JAPAN" in body:
        city = re.sub(r"<[^>]+>", "", body).strip()
        return ProbeResult("yes", region="JP", detail=city[:80])
    return ProbeResult("unknown")


def probe_dmm(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request(
            "https://api-p.videomarket.jp/v3/api/play/keyauth?playKey=4c9e93baa7ca1fc0b63ccf418275afc2&deviceType=3&bitRate=0&loginFlag=0&connType=",
            headers={"X-Authorization": "2bCf81eLJWOnHuqg6nNaPZJWfnuniPTKz9GXv5IS"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "Access is denied" in body:
        return ProbeResult("no")
    if "PlayKey has expired" in body:
        return ProbeResult("yes", region="JP")
    return ProbeResult("unknown")


def probe_unext(client: HTTPClient) -> ProbeResult:
    payload = {
        "operationName": "cosmo_getPlaylistUrl",
        "variables": {
            "code": "ED00467205",
            "playMode": "caption",
            "bitrateLow": 192,
            "bitrateHigh": None,
            "validationOnly": False,
        },
        "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) { webfront_playlistUrl(code: $code, playMode: $playMode, bitrateLow: $bitrateLow, bitrateHigh: $bitrateHigh, validationOnly: $validationOnly) { resultStatus result { errorCode errorMessage } } }",
    }
    try:
        _, _, body = client.request(
            "https://cc.unext.jp/",
            method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    result_status = str(json_from(body).get("data", {}).get("webfront_playlistUrl", {}).get("resultStatus", ""))
    if result_status in {"200", "475"}:
        return ProbeResult("yes", region="JP")
    if result_status == "467":
        return ProbeResult("no")
    return ProbeResult("unknown", detail=f"resultStatus={result_status or 'missing'}")


def probe_tver(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request(
            "https://playback.api.streaks.jp/v1/projects/tver-simul-ntv/medias/ref:simul-ntv",
            headers={"x-streaks-api-key": "ntv"},
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return ProbeResult("no")
        return ProbeResult("error", error=str(exc))
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "project_id" in body:
        return ProbeResult("yes", region="JP")
    if "403" in body:
        return ProbeResult("no")
    return ProbeResult("unknown")


def probe_hulu_jp(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, _ = client.request("https://id.hulu.jp")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    marker = f"{final_url}{code}".lower()
    if "restrict" in marker or code == 403:
        return ProbeResult("no")
    return ProbeResult("yes", region="JP")


def probe_nhk_plus(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://location-plus.nhk.jp/geoip/area.json")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    data = json_from(body)
    if data.get("area") or data.get("country") == "JP":
        return ProbeResult("yes", region="JP")
    if body:
        return ProbeResult("no", detail=body[:100])
    return ProbeResult("unknown")


def probe_spotify(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://www.spotify.com/tw/signup")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "country" in body.lower() or "signup" in body.lower():
        return ProbeResult("yes")
    return ProbeResult("unknown")


def probe_paramount(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, _ = client.request("https://www.paramountplus.com/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "intl" in final_url or code == 403:
        return ProbeResult("no")
    if code == 200:
        path = urllib.parse.urlparse(final_url).path.strip("/").split("/")
        region = path[0].upper() if path and len(path[0]) == 2 else "US"
        return ProbeResult("yes", region=region)
    return ProbeResult("unknown", detail=f"HTTP {code}")


def probe_google_ai(client: HTTPClient) -> ProbeResult:
    try:
        code, _, body = client.request(
            "https://gemini.google.com/_/BardChatUi/data/batchexecute",
            method="POST",
            data=b'f.req=[[["K4WWud","[[0],[\\"en-US\\"]]",null,"generic"]]]',
            headers={"accept-language": "en-US", "Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "SNlM0e" in body or "wrb.fr" in body:
        return ProbeResult("yes")
    if "unsupported" in body.lower() or code in {403, 451}:
        return ProbeResult("no")
    return ProbeResult("unknown", detail=f"HTTP {code}")


def probe_chatgpt(client: HTTPClient) -> ProbeResult:
    try:
        code, _, body = client.request("https://chatgpt.com/")
        _, _, trace = client.request("https://chatgpt.com/cdn-cgi/trace")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region_match = re.search(r"(?m)^loc=([A-Z]{2})$", trace)
    region = region_match.group(1) if region_match else None
    lowered = body.lower()
    if "unsupported country" in lowered or "not available in your country" in lowered:
        return ProbeResult("no", region=region)
    if code in {200, 403}:
        return ProbeResult("unknown", region=region, detail="web page is not a reliable unlock signal")
    return ProbeResult("unknown", region=region, detail=f"HTTP {code}")


def probe_sora(client: HTTPClient) -> ProbeResult:
    try:
        code, _, body = client.request("https://sora.com/")
        _, _, trace = client.request("https://sora.com/cdn-cgi/trace")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region_match = re.search(r"(?m)^loc=([A-Z]{2})$", trace)
    region = region_match.group(1) if region_match else None
    lowered = body.lower()
    if "unsupported" in lowered or "not available" in lowered:
        return ProbeResult("no", region=region)
    return ProbeResult("unknown", region=region, detail=f"HTTP {code}")


def probe_claude(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, _ = client.request("https://claude.ai/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    marker = f"{final_url}".lower()
    if "unavailable" in marker:
        return ProbeResult("no")
    if code in {200, 403}:
        return ProbeResult("unknown", detail="web page is not a reliable unlock signal")
    return ProbeResult("unknown", detail=f"HTTP {code}")


def probe_bahamut(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://ani.gamer.com.tw/ajax/getdeviceid.php")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "deviceid" in body:
        return ProbeResult("unknown", detail="device id available; token probe omitted")
    return ProbeResult("no")


def probe_bilibili_hmt(client: HTTPClient) -> ProbeResult:
    return probe_bilibili_playurl(client, "183799", "HK/MO/TW")


def probe_bilibili_tw(client: HTTPClient) -> ProbeResult:
    return probe_bilibili_playurl(client, "268176", "TW")


def probe_bilibili_global(region: str, ep_id: str) -> Callable[[HTTPClient], ProbeResult]:
    def probe(client: HTTPClient) -> ProbeResult:
        try:
            _, _, body = client.request(
                "https://api.bilibili.tv/intl/gateway/web/playurl"
                f"?s_locale=en_US&platform=web&ep_id={ep_id}",
            )
        except Exception as exc:
            return ProbeResult("error", error=str(exc))
        code = json_from(body).get("code")
        if code == 0:
            return ProbeResult("yes", region=region)
        if code is not None:
            return ProbeResult("no", region=region, detail=f"code={code}")
        return ProbeResult("unknown", region=region)

    return probe


def probe_bilibili_playurl(client: HTTPClient, ep_id: str, region: str) -> ProbeResult:
    url = (
        "https://api.bilibili.com/pgc/player/web/playurl"
        f"?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id={ep_id}&fourk=1&fnver=0&fnval=16&session=akdnswizard&module=bangumi"
    )
    try:
        _, _, body = client.request(url)
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    code = json_from(body).get("code")
    if code == 0:
        return ProbeResult("yes", region=region)
    if code == -10403:
        return ProbeResult("no", region=region)
    return ProbeResult("unknown", region=region, detail=f"code={code}")


def probe_bbc_iplayer(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://open.live.bbc.co.uk/mediaselector/6/select/version/2.0/mediaset/pc/vpid/bbc_one_london/format/json/jsfunc/JS_callbacks0")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "geolocation" in body.lower():
        return ProbeResult("no", region="GB")
    if body:
        return ProbeResult("yes", region="GB")
    return ProbeResult("unknown")


def probe_hbo_now(client: HTTPClient) -> ProbeResult:
    try:
        _, final_url, _ = client.request("https://play.hbonow.com/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    lowered = final_url.lower()
    if "geo" in lowered:
        return ProbeResult("no", region="US")
    if "play.hbonow.com" in lowered:
        return ProbeResult("yes", region="US")
    return ProbeResult("unknown", detail=final_url)


def probe_now_e(client: HTTPClient) -> ProbeResult:
    payload = {"contentId": "202105121370235", "contentType": "Vod", "pin": "", "deviceId": "W-60b8d30a-9294-d251-617b-6oagagn3", "deviceType": "WEB"}
    return probe_json_code(
        client,
        "https://webtvapi.nowe.com/16/1/getVodURL",
        ("responseCode",),
        {"NOT_LOGIN", "SUCCESS", "PRODUCT_INFORMATION_INCOMPLETE"},
        {"GEO_CHECK_FAIL"},
        method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        region="HK",
    )


def probe_paravi(client: HTTPClient) -> ProbeResult:
    payload = {"meta_id": 17414, "vuid": "3b64a775a4e38d90cc43ea4c7214702b", "device_code": 1, "app_id": 1}
    return probe_json_code(
        client,
        "https://api.paravi.jp/api/v1/playback/auth",
        ("type",),
        {"Unauthorized"},
        {"Forbidden"},
        method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        region="JP",
    )


def probe_wowow(client: HTTPClient) -> ProbeResult:
    payload = {"meta_id": 81174}
    return probe_json_code(
        client,
        "https://mapi.wowow.co.jp/api/v1/playback/auth",
        ("error", "code"),
        {"2041", "2003"},
        {"2055"},
        method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        region="JP",
    )


def probe_sling(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://p-geo.movetv.com/geo")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    data = json_from(body)
    region = str(data.get("country") or "").upper() or None
    if data.get("ip_restricted") is True:
        return ProbeResult("no", region=region)
    if "ip_restricted" in data:
        return ProbeResult("yes", region=region)
    return ProbeResult("unknown", region=region)


def probe_pluto(client: HTTPClient) -> ProbeResult:
    try:
        _, final_url, _ = client.request("https://pluto.tv/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "thanks-for-watching" in final_url:
        return ProbeResult("no")
    return ProbeResult("yes")


def probe_channel4(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://www.channel4.com/simulcast/channels/C4", {200}, {403})


def probe_itvhub(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://simulcast.itv.com/playlist/itvonline/ITV", {404}, {403})


def probe_iqiyi(client: HTTPClient) -> ProbeResult:
    try:
        code, _, body = client.request("https://www.iq.com/", method="HEAD")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region = None
    mod = None
    for line in body.splitlines():
        lowered = line.lower()
        if "x-custom-client-ip:" in lowered:
            region = line.split(":")[-1].strip().upper()
        if "mod=" in lowered:
            mod = line.split("mod=", 1)[1].split(";", 1)[0].strip()
    if region == "CN":
        return ProbeResult("partial", region=region, detail="mainland")
    if mod == "intl":
        return ProbeResult("no", region=region)
    if code:
        return ProbeResult("yes", region=region)
    return ProbeResult("unknown", region=region)


def probe_hulu_us(client: HTTPClient) -> ProbeResult:
    data = b"csrf=fdc1427eccde53326e27d7575c436595e28299dc420232ff26075ca06bbb28ed&password=Jam0.5cm~&scenario=web_password_login&user_email=me%40jamchoi.cc"
    try:
        _, _, body = client.request(
            "https://auth.hulu.com/v4/web/password/authenticate",
            method="POST",
            data=data,
            headers={"cookie": "_h_csrf_id=b0b3da20eccdc796dd61d9145a095be4927a2ff56821ad4d3f91804fd6f918ea", "Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    name = str(json_from(body).get("error", {}).get("name", ""))
    if name == "LOGIN_FORBIDDEN":
        return ProbeResult("yes", region="US")
    if name == "GEO_BLOCKED":
        return ProbeResult("no", region="US")
    return ProbeResult("unknown", detail=f"error.name={name or 'missing'}")


def probe_molotov(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://fapi.molotov.tv/v1/open-europe/is-france")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "true" in body.lower():
        return ProbeResult("yes", region="FR")
    if "false" in body.lower():
        return ProbeResult("no", region="FR")
    return ProbeResult("unknown")


def probe_salto(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://geo.salto.fr/v1/geoInfo/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    code = str(json_from(body).get("country_code") or "").upper()
    allowed = {"FR", "GP", "MQ", "GF", "RE", "YT", "PM", "BL", "MF", "WF", "PF", "NC"}
    if code in allowed:
        return ProbeResult("yes", region=code)
    if code:
        return ProbeResult("no", region=code)
    return ProbeResult("unknown")


def probe_peacock(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, _ = client.request("https://www.peacocktv.com/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "unavailable" in final_url:
        return ProbeResult("no", region="US")
    if code in {200, 403}:
        return ProbeResult("yes", region="US")
    return ProbeResult("unknown", detail=f"HTTP {code}")


def probe_britbox(client: HTTPClient) -> ProbeResult:
    try:
        _, final_url, _ = client.request("https://www.britbox.com/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "locationnotvalidated" in final_url.lower():
        return ProbeResult("no")
    return ProbeResult("yes")


def probe_youtube_premium(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://www.youtube.com/premium", headers={"Accept-Language": "en"})
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region_match = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', body)
    region = region_match.group(1) if region_match else None
    if "www.google.cn" in body:
        return ProbeResult("no", region="CN")
    if "purchaseButtonOverride" in body or "Start trial" in body or region:
        return ProbeResult("yes", region=region)
    return ProbeResult("no", region=region)


def probe_youtube_cdn(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://redirector.googlevideo.com/report_mapping?di=no")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    node = (body.split() + [""])[2]
    if node:
        return ProbeResult("yes", detail=f"cdn={node}")
    return ProbeResult("unknown")


def probe_prime_video(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://www.primevideo.com")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    match = re.search(r'"currentTerritory"\s*:\s*"([A-Z]{2})"', body)
    if match:
        return ProbeResult("yes", region=match.group(1))
    return ProbeResult("unknown")


def probe_hotstar(client: HTTPClient) -> ProbeResult:
    try:
        code, _, _ = client.request("https://api.hotstar.com/o/v1/page/1557?offset=0&size=20&tao=0&tas=20")
        _, final_url, _ = client.request("https://www.hotstar.com")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if code == 401:
        region = urllib.parse.urlparse(final_url).path.strip("/").split("/", 1)[0].upper() or None
        return ProbeResult("yes", region=region)
    if code == 475:
        return ProbeResult("no")
    return ProbeResult("unknown", detail=f"HTTP {code}")


def probe_dmm_tv(client: HTTPClient) -> ProbeResult:
    payload = {"player_name": "dmmtv_browser", "player_version": "0.0.0", "content_type_detail": "VOD_SVOD", "content_id": "11uvjcm4fw2wdu7drtd1epnvz", "purchase_product_id": None}
    return probe_markers(
        client,
        "https://api.beacon.dmm.com/v1/streaming/start",
        yes_markers={"UNAUTHORIZED"},
        no_markers={"FOREIGN"},
        method="POST",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )


def probe_litv(client: HTTPClient) -> ProbeResult:
    payload = b'{"AssetId":"iNEWS","MediaType":"channel","puid":"b0b59472-72eb-4e06-b0b1-591716e4f9a4"}'
    return probe_json_code(
        client,
        "https://www.litv.tv/api/get-urls-no-auth",
        ("error", "code"),
        {"42000075"},
        {"42000087"},
        method="POST",
        data=payload,
        headers={"Content-Type": "application/json"},
        region="TW",
    )


def probe_fubo(client: HTTPClient) -> ProbeResult:
    return probe_markers(client, "https://api.fubo.tv/appconfig/v1/homepage?platform=web&client_version=R20230310.1&nav=v0", yes_codes={200}, no_markers={"Forbidden IP"})


def probe_fox(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://x-live-fox-stgec.uplynk.com/ausw/slices/8d1/d8e6eec26bf544f084bad49a7fa2eac5/8d1de292bcc943a6b886d029e6c0dc87/G00000000.ts?pbs=c61e60ee63ce43359679fb9f65d21564&cloud=aws&si=0", {200}, {403})


def probe_popcornflix(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://popcornflix-prod.cloud.seachange.com/cms/popcornflix/clientconfiguration/versions/2", {200}, {403})


def probe_tubi(client: HTTPClient) -> ProbeResult:
    try:
        _, final_url, _ = client.request("https://tubitv.com")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "gdpr.tubi.tv" in final_url:
        return ProbeResult("no")
    return ProbeResult("yes")


def probe_philo(client: HTTPClient) -> ProbeResult:
    return probe_json_code(client, "https://content-us-east-2-fastly-b.www.philo.com/geo", ("status",), {"SUCCESS"}, {"FAIL"}, region="US")


def probe_crunchyroll(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://c.evidon.com/geo/country.js")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "'code':'us'" in body.lower():
        return ProbeResult("yes", region="US")
    return ProbeResult("no")


def probe_wavve(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://apis.wavve.com/fz/streaming?device=pc&partner=pooq&apikey=E5F3E0D30947AA5440556471321BB6D9&credential=none&service=wavve&pooqzone=none&region=kor&drm=pr&targetage=all&contentid=MV_C3001_C300000012559&contenttype=movie&hdr=sdr&videocodec=avc&audiocodec=ac3&issurround=n&format=normal&withinsubtitle=n&action=dash&protocol=dash&quality=auto", {200}, {403})


def probe_coupang(client: HTTPClient) -> ProbeResult:
    try:
        _, final_url, _ = client.request("https://www.coupangplay.com/")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "not-available" in final_url:
        return ProbeResult("no", region="KR")
    return ProbeResult("yes", region="KR")


def probe_kocowa(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://www.kocowa.com/", {200}, {403})


def probe_panda_tv(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://api.pandalive.co.kr/v1/live/play", {400}, {403})


def probe_crackle(client: HTTPClient) -> ProbeResult:
    try:
        code, _, body = client.request("https://prod-api.crackle.com/appconfig", method="HEAD")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    if "x-crackle-region" in body.lower() or code == 200:
        return ProbeResult("yes")
    return ProbeResult("unknown", detail=f"HTTP {code}")


def probe_youtube(client: HTTPClient) -> ProbeResult:
    premium = probe_youtube_premium(client)
    if premium.status in {"yes", "partial", "no"}:
        return premium
    cdn = probe_youtube_cdn(client)
    if cdn.status == "yes":
        return ProbeResult("yes", region=premium.region, detail=cdn.detail)
    return premium if premium.status != "unknown" else cdn


def probe_reddit(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, body = client.request("https://www.reddit.com/", headers={"Accept-Language": "en"})
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    marker = f"{final_url}\n{body}".lower()
    if "blocked in your country" in marker or "not available in your location" in marker:
        return ProbeResult("no")
    if code in {200, 403, 429}:
        return ProbeResult("yes", detail=f"HTTP {code}")
    return ProbeResult("unknown", detail=f"HTTP {code} {final_url}")


def probe_meta_ai(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, body = client.request("https://www.meta.ai/", headers={"Accept-Language": "en"})
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    marker = f"{final_url}\n{body}".lower()
    if "not available in your country" in marker or "isn't available in your country" in marker:
        return ProbeResult("no")
    if "meta ai" in marker and code in {200, 403}:
        return ProbeResult("unknown", detail="web page is not a reliable unlock signal")
    return ProbeResult("unknown", detail=f"HTTP {code} {final_url}")


def probe_google_play(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, body = client.request("https://play.google.com/store/apps/details?id=com.google.android.gms", headers={"Accept-Language": "en"})
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region_match = re.search(r'"gl"\s*:\s*"([A-Z]{2})"', body)
    region = region_match.group(1) if region_match else None
    marker = f"{final_url}\n{body}".lower()
    if "not available in your country" in marker:
        return ProbeResult("no", region=region)
    if code == 200 and ("google play" in marker or "play.google.com" in final_url):
        return ProbeResult("yes", region=region, detail="store reachable")
    return ProbeResult("unknown", region=region, detail=f"HTTP {code}")


def probe_apple_ai(client: HTTPClient) -> ProbeResult:
    try:
        _, _, body = client.request("https://gspe1-ssl.ls.apple.com/pep/gcc")
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    region = body.strip().upper()[:2]
    if re.fullmatch(r"[A-Z]{2}", region):
        blocked = {"CN", "HK", "MO"}
        status = "no" if region in blocked else "unknown"
        return ProbeResult(status, region=region, detail="Apple country code; Apple Intelligence availability also depends on device, OS, language, and account")
    return ProbeResult("unknown", detail="missing Apple country code")


def probe_watcha(client: HTTPClient) -> ProbeResult:
    try:
        code, final_url, body = client.request("https://watcha.com/", headers={"Accept-Language": "en"})
    except Exception as exc:
        return ProbeResult("error", error=str(exc))
    marker = f"{final_url}\n{body}".lower()
    if "not available" in marker or "unsupported country" in marker or code in {403, 451}:
        return ProbeResult("no", region="KR", detail=f"HTTP {code}")
    if code == 200 and "watcha" in marker:
        return ProbeResult("unknown", region="KR", detail="home page reachable; playback entitlement not verified")
    return ProbeResult("unknown", region="KR", detail=f"HTTP {code}")


def probe_sd_gundam(client: HTTPClient) -> ProbeResult:
    return probe_url_status(client, "https://api.eternal.channel.or.jp/", {404}, {403, 451}, headers={"User-Agent": UA_DALVIK})


def probe_vodio_status(url: str, yes_codes: set[int] = {200}, no_codes: set[int] = {403, 451}) -> Callable[[HTTPClient], ProbeResult]:
    return lambda client: probe_url_status(client, url, yes_codes, no_codes)


NATIVE_PROBES: dict[str, Callable[[HTTPClient], ProbeResult]] = {
    "Abema TV": probe_abema,
    "Netflix": probe_netflix,
    "Dazn": probe_dazn,
    "MyTVSuper": probe_mytvsuper,
    "Viu.TV": probe_viutv,
    "Viu.com": probe_viu_com,
    "KKTV": probe_kktv,
    "Line TV": probe_linetv,
    "Hami Video": probe_hami,
    "4GTV": probe_4gtv,
    "CatchPlay+": probe_catchplay,
    "Friday Video": probe_friday,
    "动画疯": probe_bahamut,
    "Bilibili 港澳台": probe_bilibili_hmt,
    "Bilibili": probe_bilibili_hmt,
    "Bilibili Hong Kong/Macau/Taiwan": probe_bilibili_hmt,
    "Bilibili Taiwan": probe_bilibili_tw,
    "Bilibili Global SouthEastAsia": probe_bilibili_global("SEA", "347666"),
    "Bilibili Global Thailand": probe_bilibili_global("TH", "10077726"),
    "Bilibili Global Indonesia": probe_bilibili_global("ID", "11130043"),
    "Bilibili Global Vietnam": probe_bilibili_global("VN", "11405745"),
    "NicoNico": probe_niconico,
    "MGStage": probe_mgstage,
    "FOD(Fuji TV)": probe_fod,
    "Radiko": probe_radiko,
    "DMM": probe_dmm,
    "U-NEXT": probe_unext,
    "TVer": probe_tver,
    "Hulu Japan": probe_hulu_jp,
    "NHK+": probe_nhk_plus,
    "Now E": probe_now_e,
    "Paravi": probe_paravi,
    "WOWOW": probe_wowow,
    "BBC iPLAYER": probe_bbc_iplayer,
    "HBO Now": probe_hbo_now,
    "Sling TV": probe_sling,
    "Pluto TV": probe_pluto,
    "Channel 4": probe_channel4,
    "ITV Hub": probe_itvhub,
    "iQyi Oversea": probe_iqiyi,
    "Hulu US": probe_hulu_us,
    "Molotov": probe_molotov,
    "Salto": probe_salto,
    "Peacock TV": probe_peacock,
    "BritBox": probe_britbox,
    "YouTube Premium": probe_youtube_premium,
    "YouTube CDN": probe_youtube_cdn,
    "Amazon Prime Video": probe_prime_video,
    "HotStar": probe_hotstar,
    "DMM TV": probe_dmm_tv,
    "LiTV": probe_litv,
    "Fubo TV": probe_fubo,
    "FOX": probe_fox,
    "Popcornflix": probe_popcornflix,
    "Tubi TV": probe_tubi,
    "Philo": probe_philo,
    "Crunchyroll": probe_crunchyroll,
    "Wavve": probe_wavve,
    "Coupang Play": probe_coupang,
    "KOCOWA": probe_kocowa,
    "Panda TV": probe_panda_tv,
    "Crackle": probe_crackle,
    "Youtube": probe_youtube,
    "Google Play": probe_google_play,
    "Apple AI": probe_apple_ai,
    "Meta AI": probe_meta_ai,
    "Reddit": probe_reddit,
    "WATCHA": probe_watcha,
    "SD Gundam G Generation Eternal": probe_sd_gundam,
    "Spotify": probe_spotify,
    "Paramount+": probe_paramount,
    "Google AI": probe_google_ai,
    "ChatGPT": probe_chatgpt,
    "Sora": probe_sora,
    "Claude": probe_claude,
    "Princess Connect Re:Dive Japan": lambda c: probe_url_status(c, "https://api-priconne-redive.cygames.jp/", {404}, {403}, headers={"User-Agent": UA_DALVIK}),
    "Pretty Derby Japan": lambda c: probe_url_status(c, "https://api-umamusume.cygames.jp/", {404}, {403}, headers={"User-Agent": UA_DALVIK}),
    "Karaoke@DAM": lambda c: probe_url_status(c, "https://www.clubdam.com/", {200}, {403}),
    "J:com On Demand": lambda c: probe_url_status(c, "https://id.zaq.ne.jp", {200}, {403}),
    "Mora": lambda c: probe_url_status(c, "https://mora.jp/", {200}, {403}),
    "D Anime Store": lambda c: probe_url_status(c, "https://animestore.docomo.ne.jp/animestore/reg_pc", {200}, {403}),
    "EroGameSpace": lambda c: probe_url_status(c, "https://erogamescape.org", {200}, {403}),
}

NATIVE_PROBE_INDEX = {normalize_name(name): probe for name, probe in NATIVE_PROBES.items()}


def native_probe(name: str) -> Callable[[HTTPClient], ProbeResult] | None:
    return NATIVE_PROBES.get(name) or NATIVE_PROBE_INDEX.get(normalize_name(name))


def has_native_probe(name: str, check_function: str | None = None) -> bool:
    return bool(check_function) or native_probe(name) is not None


def service_has_probe(service: Service) -> bool:
    return has_native_probe(service.name, service.check_function)


def probe_source_label(service: Service) -> str:
    if service.check_function:
        return "check.sh"
    if native_probe(service.name):
        return "builtin"
    return "unknown"


def parse_check_json_line(line: str) -> ProbeResult | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    status = str(data.get("status") or "unknown").lower()
    if status not in {"yes", "no", "partial", "unknown", "error"}:
        status = "unknown"
    return ProbeResult(
        status=status,
        region=str(data.get("region") or "") or None,
        detail=str(data.get("detail") or ""),
    )


def merge_probe_results(results: list[ProbeResult]) -> ProbeResult:
    if not results:
        return ProbeResult("unknown", detail="check.sh returned no machine-readable result")
    order = {"yes": 0, "partial": 1, "no": 2, "unknown": 3, "error": 4}
    best = sorted(results, key=lambda result: order.get(result.status, 5))[0]
    regions = dedupe(result.region for result in results if result.region)
    details = []
    for index, result in enumerate(results, 1):
        detail = result.detail.strip().replace("\r", " ").replace("\n", " ")
        if detail:
            details.append(f"v{index}:{detail}")
    return ProbeResult(best.status, region="/".join(regions) or best.region, detail=" | ".join(details[:2]))


def resolve_check_bash() -> str | None:
    global _CHECK_BASH_CACHE
    if _CHECK_BASH_CACHE is not False:
        return _CHECK_BASH_CACHE
    configured = os.environ.get("AKDNS_CHECK_BASH", "").strip()
    bash = configured or shutil.which("bash")
    if not bash:
        _CHECK_BASH_CACHE = None
        return None
    try:
        proc = subprocess.run(
            [bash, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        _CHECK_BASH_CACHE = None
        return None
    if proc.returncode != 0 or "GNU bash" not in (proc.stdout + proc.stderr):
        _CHECK_BASH_CACHE = None
        return None
    _CHECK_BASH_CACHE = bash
    return bash


def run_check_sh_probe(service: Service, timeout: float, ip_version: str, check_path: Path | None = None) -> ProbeResult | None:
    if not service.check_function:
        return None
    resolved_check_path = check_path or Path(__file__).resolve().with_name(CHECK_FILE)
    if not resolved_check_path.exists():
        return ProbeResult("unknown", detail="check.sh not found")
    bash = resolve_check_bash()
    if not bash:
        return ProbeResult("unknown", detail="bash not found; set AKDNS_CHECK_BASH to enable check.sh probes")
    mode_args = []
    if ip_version in {"4", "6"}:
        mode_args = ["-M", ip_version]
    command = [bash, str(resolved_check_path), "-J", *mode_args, "-F", service.check_function]
    try:
        with tempfile.TemporaryDirectory(prefix="akdns-check-") as tmp:
            proc = subprocess.run(
                command,
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=max(5, int(timeout) * 3),
                encoding="utf-8",
                errors="replace",
            )
    except FileNotFoundError:
        return ProbeResult("unknown", detail="bash not found; check.sh probe unavailable")
    except subprocess.TimeoutExpired:
        return ProbeResult("error", detail="check.sh timed out")
    results = [result for line in proc.stdout.splitlines() if (result := parse_check_json_line(line))]
    if results:
        return merge_probe_results(results)
    detail = (proc.stderr or proc.stdout).strip()
    if not detail and proc.returncode:
        detail = f"check.sh exited with {proc.returncode}"
    return ProbeResult("error" if proc.returncode else "unknown", detail=detail[:300])


def run_probe(service: Service, timeout: float, ip_version: str, check_path: Path | None = None) -> ProbeResult:
    check_result = run_check_sh_probe(service, timeout, ip_version, check_path)
    if check_result is not None:
        return check_result
    probe = native_probe(service.name)
    if probe is None:
        return ProbeResult("unknown", detail="no reliable native probe")
    client = HTTPClient(timeout=timeout, ip_version=ip_version)
    try:
        return probe(client)
    except Exception as exc:
        return ProbeResult("error", error=str(exc))


def test_worker_count(total: int) -> int:
    if total <= 0:
        return 0
    if total <= 1:
        return 1
    raw = os.environ.get(TEST_WORKERS_ENV, "").strip()
    if raw:
        with contextlib.suppress(ValueError):
            return max(1, min(total, int(raw)))
    return max(1, min(total, 4))


def run_probe_batch(
    services: list[Service],
    *,
    timeout: float = DEFAULT_TEST_TIMEOUT,
    ip_version: str = "auto",
    check_path: Path | None = None,
) -> Iterable[tuple[int, Service, ProbeResult, int]]:
    total = len(services)
    if not services:
        return
    workers = test_worker_count(total)
    if workers == 1:
        for index, service in enumerate(services, 1):
            yield index, service, run_probe(service, timeout=timeout, ip_version=ip_version, check_path=check_path), total
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_service = {
            executor.submit(run_probe, service, timeout, ip_version, check_path): service
            for service in services
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_to_service):
            completed += 1
            service = future_to_service[future]
            try:
                result = future.result()
            except Exception as exc:
                result = ProbeResult("error", error=str(exc))
            yield completed, service, result, total


def status_label(status: str, lang: str) -> str:
    return TEXT[lang].get(status, status)


def service_matches_regions(service: Service, selected_regions: set[str]) -> bool:
    if not selected_regions:
        return True
    hints = {("GB" if item.upper() == "UK" else item.upper()) for item in service.region_hints}
    return bool(hints & selected_regions)


def normalize_region_input(value: str) -> str:
    code = value.strip().upper()
    return "GB" if code == "UK" else code


def region_sort_key(code: str) -> tuple[int, str]:
    normalized = normalize_region_input(code)
    try:
        return REGION_ORDER.index(normalized), normalized
    except ValueError:
        return len(REGION_ORDER), normalized


def available_regions(services: list[Service]) -> list[str]:
    return sorted({region for service in services for region in service.region_hints}, key=region_sort_key)


def split_test_regions(regions: Iterable[str]) -> tuple[list[str], list[tuple[str, dict[str, str], list[str]]]]:
    available = set(regions)
    primary = [region for region in PRIMARY_TEST_REGIONS if region in available]
    grouped_regions = set(primary)
    groups: list[tuple[str, dict[str, str], list[str]]] = []
    for key, labels, group_regions in TEST_REGION_GROUPS:
        current = [region for region in group_regions if region in available and region not in grouped_regions]
        grouped_regions.update(current)
        if current:
            groups.append((key, labels, current))
    remaining = [region for region in sorted(available - grouped_regions, key=region_sort_key)]
    if remaining:
        groups.append(("other-extra", {"zh": "其他地区", "en": "Other regions"}, remaining))
    return primary, groups


def region_group_counts(services: list[Service], regions: Iterable[str]) -> tuple[int, int]:
    region_set = set(regions)
    grouped = [service for service in services if region_set & set(service.region_hints)]
    return len(grouped), sum(1 for service in grouped if service_has_probe(service))


def testable_services(state: WizardState) -> list[Service]:
    return [
        service
        for service in state.services
        if service_has_probe(service) and service_matches_regions(service, state.test_regions)
    ]


def services_in_test_regions(state: WizardState) -> list[Service]:
    return [
        service
        for service in state.services
        if service_matches_regions(service, state.test_regions) and service.region_hints
    ]


def region_service_counts(services: list[Service], region: str) -> tuple[int, int]:
    total = 0
    native = 0
    for service in services:
        if region in service.region_hints:
            total += 1
            if service_has_probe(service):
                native += 1
    return total, native


def status_score(service: Service) -> int:
    order = {"no": 0, "partial": 1, "unknown": 2, "error": 3, "yes": 4}
    return order.get(service.probe_result.status, 5)


def parse_dns_servers(raw: str) -> list[str]:
    servers = []
    for item in re.split(r"[,;\s]+", raw.strip()):
        if not item:
            continue
        try:
            ipaddress.ip_address(item)
        except ValueError:
            continue
        if item not in servers:
            servers.append(item)
    return servers


def make_rules_json(services: list[Service]) -> str:
    rules = [
        {"service": service.name, "backend": service.selected_backend}
        for service in services
        if service.selected and service.selected_backend
    ]
    return json.dumps({"rules": rules}, ensure_ascii=False, indent=2) + "\n"


def collect_domains(services: list[Service]) -> list[str]:
    domains = []
    for service in services:
        if service.selected:
            domains.extend(service.domains)
    return dedupe(sorted(domains, key=lambda value: value.lower()))


def make_smartdns_conf(state: WizardState) -> str:
    lang = state.lang
    public_servers = state.public_dns_servers
    domains = collect_domains(state.services)
    lines = [
        "# Generated by akdns-wizard.py",
        "# Default public DNS handles normal domains; AKDNS is used only by nameserver rules below.",
        "# Listen on loopback only; expose this resolver explicitly if LAN access is required.",
        "",
        "bind 127.0.0.1:53",
        "bind [::1]:53",
        "bind-tcp 127.0.0.1:53",
        "bind-tcp [::1]:53",
        "cache-size 32768",
        "prefetch-domain yes",
        "serve-expired yes",
        "serve-expired-ttl 86400",
        "serve-expired-reply-ttl 3",
        "speed-check-mode ping,tcp:80,tcp:443",
        "dualstack-ip-selection yes",
        "dualstack-ip-selection-threshold 10",
        "response-mode fastest-response",
        "log-level notice",
        "",
        "# Public DNS: default upstreams for all non-unlock domains.",
    ]
    for server in public_servers:
        lines.append(f"server {server}")
    lines.extend(
        [
            "",
            "# AKDNS unlock group: excluded from default group so normal domains do not use it.",
            "# SmartDNS performs real-time resolver and IP selection with speed-check-mode/response-mode.",
        ]
    )
    for server in state.akdns_servers:
        lines.append(f"server {server} -group akdns-unlock -exclude-default-group")
    lines.extend(
        [
            "",
            "# Fallback only after AKDNS upstreams fail. This preserves unlock behavior during normal operation.",
        ]
    )
    for server in public_servers[:2]:
        lines.append(f"server {server} -group akdns-unlock -exclude-default-group -fallback")
    lines.extend(["", "# Unlock domain split rules."])
    for domain in domains:
        lines.append(f"nameserver /{domain}/akdns-unlock")
    if not domains:
        lines.append("# No domains selected.")
    lines.extend(
        [
            "",
            f"# Selected AKDNS backend rules are written to {DEFAULT_OUTPUT_FILES['rules']}.",
            f"# UI language: {'Chinese' if lang == 'zh' else 'English'}",
            f"# AKDNS resolvers: {', '.join(state.akdns_servers)}",
        ]
    )
    return "\n".join(lines) + "\n"


def default_output_paths() -> dict[str, Path]:
    return {key: Path.cwd() / name for key, name in DEFAULT_OUTPUT_FILES.items()}


def output_paths(state: WizardState) -> dict[str, Path]:
    paths = default_output_paths()
    paths.update(state.output_paths)
    return paths


def selected_services(state: WizardState) -> list[Service]:
    return selected_services_from(state.services)


def dns_summary(servers: list[str], limit: int = 3) -> str:
    visible = servers[:limit]
    suffix = f", +{len(servers) - limit}" if len(servers) > limit else ""
    return ", ".join(visible) + suffix if visible else "-"


def final_plan_rows(state: WizardState) -> list[str]:
    lang = state.lang
    selected = selected_services(state)
    domains = collect_domains(state.services)
    paths = output_paths(state)
    unresolved_locked = [
        service
        for service in state.services
        if service_matches_strategy_scope(service, LOCKED_STRATEGY_STATUSES, True)
    ]
    dns_profile = PUBLIC_DNS_PROFILES.get(state.dns_profile, {}).get(lang, state.dns_profile)
    rows = [
        (
            "已选择平台" if lang == "zh" else "Selected services",
            str(len(selected)),
            "将写入 akdns-rules" if lang == "zh" else "Will be written to akdns-rules",
        ),
        (
            "分流域名" if lang == "zh" else "Split domains",
            str(len(domains)),
            "只这些域名走解锁 DNS" if lang == "zh" else "Only these domains use unlock DNS",
        ),
        (
            "未处理未解锁" if lang == "zh" else "Unhandled locked",
            str(len(unresolved_locked)),
            "保留现状，不自动分流" if lang == "zh" else "Left unchanged, not auto-split",
        ),
        (
            "公共 DNS" if lang == "zh" else "Public DNS",
            dns_profile,
            dns_summary(state.public_dns_servers),
        ),
        (
            "解锁 DNS" if lang == "zh" else "Unlock DNS",
            str(len(state.akdns_servers)),
            dns_summary(state.akdns_servers),
        ),
        (
            "规则文件" if lang == "zh" else "Rules file",
            paths["rules"].name,
            str(paths["rules"].parent),
        ),
        (
            "SmartDNS 文件" if lang == "zh" else "SmartDNS file",
            paths["smartdns"].name,
            str(paths["smartdns"].parent),
        ),
    ]
    headers = ("项目", "值", "说明") if lang == "zh" else ("Item", "Value", "Notes")
    lines = [
        format_columns([(headers[0], 16), (headers[1], 22), (headers[2], 56)]),
    ]
    lines.extend(format_columns([(name, 16), (value, 22), (note, 56)]) for name, value, note in rows)
    if not selected:
        lines.append("没有选择任何平台，保存后规则为空。" if lang == "zh" else "No services selected; saved rules will be empty.")
    return lines


def backend_usage_table_lines(state: WizardState) -> list[str]:
    counts: dict[str, int] = {}
    for service in selected_services(state):
        counts[service.selected_backend or ""] = counts.get(service.selected_backend or "", 0) + 1
    if not counts:
        return []
    lang = state.lang
    headers = ("backend", "地区", "平台") if lang == "zh" else ("Backend", "Region", "Services")
    lines = [format_columns([(headers[0], 26), (headers[1], 16), (headers[2], 8)])]
    for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        backend = state.backends.get(name)
        region = region_name(backend_region(backend), lang) if backend else "-"
        lines.append(format_columns([(format_backend(backend, lang), 26), (region, 16), (count, 8)]))
    return lines


def final_summary_lines(state: WizardState) -> list[str]:
    return [("最终生成计划" if state.lang == "zh" else "Final generation plan"), *final_plan_rows(state)]


def final_preview_lines(state: WizardState, limit: int = 200) -> list[str]:
    lang = state.lang
    lines = final_summary_lines(state)
    probe_lines = probe_result_lines(state, limit=limit)
    if probe_lines:
        lines.append("")
        lines.append("检测结果:" if lang == "zh" else "Probe results:")
        lines.extend(probe_lines)
    usage = backend_usage_table_lines(state)
    if usage:
        lines.append("")
        lines.append("backend 使用分布:" if lang == "zh" else "Backend usage:")
        lines.extend(usage)
    lines.append("")
    lines.append("分流规则:" if lang == "zh" else "Split rules:")
    selected = selected_services(state)
    if not selected:
        lines.append("  -")
    headers = ("平台", "backend", "状态", "域名", "支持backend区域") if lang == "zh" else ("Service", "Backend", "Status", "Domains", "Supported backend regions")
    if selected:
        lines.append(format_columns([(headers[0], 28), (headers[1], 22), (headers[2], 10), (headers[3], 8), (headers[4], 32)]))
    for service in selected[:limit]:
        backend = state.backends.get(service.selected_backend or "")
        domain_count = len(service.domains)
        status = status_label(service.probe_result.status, lang)
        supported_regions = format_region_list(candidate_regions(service, state.backends), lang, limit=6)
        lines.append(format_columns([(service.name, 28), (format_backend(backend, lang), 22), (status, 10), (domain_count, 8), (supported_regions, 32)]))
    if len(selected) > limit:
        lines.append(f"  ... {len(selected) - limit} more")
    return lines


def probe_result_lines(state: WizardState, limit: int = 200) -> list[str]:
    lang = state.lang
    services = [service for service in state.services if not state.tested_services or service.name in state.tested_services]
    if not services:
        return []
    headers = ("平台", "状态", "服务区域", "检测区域", "来源") if lang == "zh" else ("Service", "Status", "Service regions", "Detected", "Source")
    lines = [format_columns([(headers[0], 30), (headers[1], 10), (headers[2], 34), (headers[3], 14), (headers[4], 14)])]
    for service in sorted(services, key=lambda item: (status_score(item), item.name.lower()))[:limit]:
        status = status_label(service.probe_result.status, lang)
        detected = region_name(service.probe_result.region, lang) if service.probe_result.region else "-"
        source = TEXT[lang]["catalog"] if service.configurable else TEXT[lang]["check_only"]
        regions = format_region_list(service.region_hints, lang, limit=4)
        lines.append(format_columns([(service.name, 30), (status, 10), (regions, 34), (detected, 14), (source, 14)]))
    if len(services) > limit:
        lines.append(f"  ... {len(services) - limit} more")
    return lines


def report_summary_lines(state: WizardState) -> list[str]:
    counts: dict[str, int] = {}
    scoped = [service for service in state.services if not state.tested_services or service.name in state.tested_services]
    for service in scoped:
        counts[service.probe_result.status] = counts.get(service.probe_result.status, 0) + 1
    selected = sum(1 for service in state.services if service.selected)
    lang = state.lang
    regions = format_region_list(sorted(state.test_regions), lang) if state.test_regions else (TEXT[lang]["region_all"])
    rows = [
        ("检测区域" if lang == "zh" else "Test regions", regions),
        ("检测范围平台" if lang == "zh" else "Services in scope", str(len(scoped))),
        (status_label("yes", lang), str(counts.get("yes", 0))),
        (status_label("no", lang), str(counts.get("no", 0))),
        (status_label("partial", lang), str(counts.get("partial", 0))),
        (status_label("unknown", lang), str(counts.get("unknown", 0))),
        (status_label("error", lang), str(counts.get("error", 0))),
        (TEXT[lang]["selected"], str(selected)),
    ]
    headers = ("项目", "值") if lang == "zh" else ("Item", "Value")
    lines = [
        ("检测摘要" if lang == "zh" else "Test summary"),
        format_columns([(headers[0], 18), (headers[1], 42)]),
    ]
    lines.extend(format_columns([(name, 18), (value, 42)]) for name, value in rows)
    details = probe_result_lines(state, limit=200)
    if details:
        lines.append("")
        lines.append("检测结果:" if lang == "zh" else "Probe results:")
        lines.extend(details)
    return lines


def terminal_supports_curses() -> bool:
    try:
        import curses  # noqa: F401

        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


class CursesUI:
    def __init__(self, state: WizardState) -> None:
        self.state = state

    def run(self) -> WizardResult:
        import curses

        return curses.wrapper(self._run)

    def _run(self, stdscr) -> WizardResult:  # type: ignore[no-untyped-def]
        import curses

        curses.curs_set(0)
        stdscr.keypad(True)
        step = "language"
        test_services: list[Service] = []
        while True:
            try:
                if step == "language":
                    self.choose_language(stdscr, allow_back=False)
                    step = "mode"
                elif step == "mode":
                    self.choose_mode(stdscr)
                    step = "dns"
                elif step == "dns":
                    self.choose_dns_profile(stdscr)
                    step = "akdns"
                elif step == "akdns":
                    self.configure_akdns_servers(stdscr)
                    step = "test-regions" if self.state.mode in {"test-only", "test-and-generate"} else "services"
                elif step == "test-regions":
                    self.choose_test_regions(stdscr)
                    step = "test-scope"
                elif step == "test-scope":
                    test_services = self.choose_test_scope(stdscr)
                    step = "run-tests"
                elif step == "run-tests":
                    self.run_tests(stdscr, test_services)
                    step = "services" if self.state.mode in {"generate-only", "test-and-generate"} else "confirm"
                elif step == "services":
                    self.choose_unlock_services(stdscr)
                    step = "confirm"
                elif step == "confirm":
                    return self.confirm_and_write(stdscr)
            except BackRequested:
                previous = self.previous_step(step)
                if previous == step:
                    continue
                step = previous

    def previous_step(self, step: str) -> str:
        if step == "mode":
            return "language"
        if step == "dns":
            return "mode"
        if step == "akdns":
            return "dns"
        if step == "test-regions":
            return "akdns"
        if step == "test-scope":
            return "test-regions"
        if step == "run-tests":
            return "test-scope"
        if step == "services":
            return "test-scope" if self.state.mode in {"test-only", "test-and-generate"} else "akdns"
        if step == "confirm":
            if self.state.mode == "test-only":
                return "run-tests"
            return "services"
        return step

    def choose_language(self, stdscr, allow_back: bool = True) -> None:  # type: ignore[no-untyped-def]
        items = [("zh", "中文"), ("en", "English")]
        default = "zh"
        title = "选择界面语言 / Choose UI Language"
        hint = "↑↓ move  Enter choose  q quit"
        self.state.lang = self.single_select(stdscr, title, items, default, hint, allow_back=allow_back)

    def choose_mode(self, stdscr) -> None:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        items = [
            ("test-and-generate", "检测后生成解锁配置" if lang == "zh" else "Test then generate unlock config"),
            ("test-only", "只测试解锁" if lang == "zh" else "Only test unlock status"),
            ("generate-only", "只生成解锁配置" if lang == "zh" else "Only generate unlock config"),
        ]
        title = "选择脚本流程" if lang == "zh" else "Choose Workflow"
        hint = "↑↓ 移动  Enter 选择  Ctrl+B 返回" if lang == "zh" else "↑↓ move  Enter choose  Ctrl+B back"
        self.state.mode = self.single_select(stdscr, title, items, self.state.mode, hint)

    def draw_header(self, stdscr, title: str, help_text: str = "", *, clear: bool = True) -> tuple[int, int]:
        import curses

        stdscr.standend()
        stdscr.attrset(curses.A_NORMAL)
        stdscr.bkgd(" ", curses.A_NORMAL)
        h, w = stdscr.getmaxyx()
        if clear:
            stdscr.erase()
        else:
            if h > 0:
                fill_curses_row(stdscr, 0, w, curses.A_NORMAL)
            if h > 1:
                fill_curses_row(stdscr, 1, w, curses.A_NORMAL)
            if h > 2:
                fill_curses_row(stdscr, h - 1, w, curses.A_NORMAL)
        lang = self.state.lang
        header = f"{APP_NAME} {VERSION}  -  {title}"
        stdscr.addnstr(0, 0, header, w - 1)
        stdscr.addnstr(1, 0, "-" * max(0, w - 1), w - 1)
        if help_text:
            stdscr.addnstr(h - 1, 0, help_text, w - 1)
        else:
            if lang == "zh":
                base = "↑↓ 移动  Space 选择  / 搜索  Enter 下一步  Ctrl+B 返回  q 退出"
            else:
                base = "↑↓ move  Space select  / search  Enter next  Ctrl+B back  q quit"
            stdscr.addnstr(h - 1, 0, base, w - 1)
        return h, w

    def is_back_key(self, key: int) -> bool:
        return key == 2  # Ctrl+B

    def is_delete_key(self, key: int) -> bool:
        import curses

        return key in (curses.KEY_BACKSPACE, 8, 127)

    def draw_row(self, stdscr, row: int, text: str, selected: bool = False) -> None:  # type: ignore[no-untyped-def]
        import curses

        _, width = stdscr.getmaxyx()
        limit = max(0, width - 1)
        line = fit_display_cells(text, limit)
        attr = curses.A_REVERSE if selected else curses.A_NORMAL
        stdscr.standend()
        stdscr.attrset(curses.A_NORMAL)
        fill_curses_row(stdscr, row, width, attr)
        col = 0
        for cluster, cluster_width in display_cell_clusters(line):
            if col + cluster_width > limit:
                break
            with contextlib.suppress(curses.error):
                stdscr.addstr(row, col, cluster, attr)
            col += cluster_width
        with contextlib.suppress(curses.error):
            stdscr.touchline(row, 1)
        stdscr.standend()

    def clear_rows(self, stdscr, start_row: int, row_count: int) -> None:  # type: ignore[no-untyped-def]
        import curses

        height, width = stdscr.getmaxyx()
        stdscr.standend()
        stdscr.attrset(curses.A_NORMAL)
        for row in range(start_row, min(height - 1, start_row + row_count)):
            fill_curses_row(stdscr, row, width, curses.A_NORMAL)

    def draw_region_list_window(
        self,
        stdscr,
        top: int,
        row_count: int,
        rendered_rows: list[tuple[str, bool]],
        force_redraw: bool = False,
        refresh: bool = True,
    ) -> None:  # type: ignore[no-untyped-def]
        if row_count <= 0:
            if refresh:
                stdscr.refresh()
            return
        if force_redraw:
            with contextlib.suppress(Exception):
                stdscr.redrawln(top, row_count)
        for row in range(row_count):
            text, is_current = rendered_rows[row] if row < len(rendered_rows) else ("", False)
            self.draw_row(stdscr, top + row, text, is_current)
        if refresh:
            stdscr.refresh()

    def choose_dns_profile(self, stdscr) -> None:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        items = [(key, value[lang]) for key, value in PUBLIC_DNS_PROFILES.items()]
        title = "选择默认公共 DNS" if lang == "zh" else "Choose Default Public DNS"
        hint = "↑↓ 移动  Enter 选择  Ctrl+B 返回" if lang == "zh" else "↑↓ move  Enter choose  Ctrl+B back"
        while True:
            selected = self.single_select(stdscr, title, items, self.state.dns_profile, hint)
            self.state.dns_profile = selected
            if selected != "custom":
                self.state.public_dns_servers = list(PUBLIC_DNS_PROFILES[selected]["servers"])
                return
            try:
                raw = self.prompt(
                    stdscr,
                    "输入公共 DNS，逗号分隔" if lang == "zh" else "Enter public DNS, comma separated",
                )
            except BackRequested:
                continue
            servers = parse_dns_servers(raw)
            if servers:
                self.state.public_dns_servers = servers
                return
            self.state.dns_profile = "cloudflare"
            self.state.public_dns_servers = list(PUBLIC_DNS_PROFILES["cloudflare"]["servers"])
            return

    def configure_akdns_servers(self, stdscr) -> None:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        answer = self.single_select(
            stdscr,
            "是否修改解锁 DNS 服务器？" if lang == "zh" else "Change AKDNS unlock resolvers?",
            [("keep", "使用脚本默认解锁 DNS" if lang == "zh" else "Use configured AKDNS defaults"), ("custom", "输入自定义解锁 DNS" if lang == "zh" else "Enter custom unlock DNS")],
            "keep",
            "↑↓ 移动  Enter 选择  Ctrl+B 返回" if lang == "zh" else "↑↓ move  Enter choose  Ctrl+B back",
        )
        if answer == "custom":
            try:
                raw = self.prompt(
                    stdscr,
                    "输入解锁 DNS，逗号分隔" if lang == "zh" else "Enter unlock DNS, comma separated",
                )
            except BackRequested:
                return self.configure_akdns_servers(stdscr)
            servers = parse_dns_servers(raw)
            if servers:
                self.state.akdns_servers = servers

    def choose_test_regions(self, stdscr) -> None:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        regions = available_regions(self.state.services)
        primary_regions, region_groups = split_test_regions(regions)
        selected = set(self.state.test_regions or regions)
        title = "选择要检测的平台地区" if lang == "zh" else "Choose Regions To Test"
        hint = (
            "顶级只显示核心地区；o 当前分组  O 全部展开/折叠  a 全选  c 清空  Space 切换  Enter 继续"
            if lang == "zh"
            else "top-level core only; o current group  O expand/collapse all  a all  c clear  Space toggle  Enter continue"
        )
        self.state.test_regions = self.region_select(stdscr, title, primary_regions, region_groups, selected, hint)

    def test_region_line(self, code: str) -> str:
        total, native = region_service_counts(self.state.services, code)
        name = region_name(code, self.state.lang)
        if self.state.lang == "zh":
            return format_columns([(name, 18), (total, 8), (native, 8)])
        return format_columns([(name, 24), (total, 10), (native, 10)])

    def test_region_group_line(self, label: str, regions: list[str]) -> str:
        total, native = region_group_counts(self.state.services, regions)
        if self.state.lang == "zh":
            return format_columns([(label, 18), (total, 8), (native, 8)])
        return format_columns([(label, 24), (total, 10), (native, 10)])

    def test_regions_header(self) -> str:
        if self.state.lang == "zh":
            return "        " + format_columns([("地区/分组", 18), ("平台", 8), ("可检测", 8)])
        return "        " + format_columns([("Region/group", 24), ("Services", 10), ("Testable", 10)])

    def region_select(
        self,
        stdscr,
        title: str,
        primary_regions: list[str],
        region_groups: list[tuple[str, dict[str, str], list[str]]],
        selected: set[str],
        hint: str,
    ) -> set[str]:  # type: ignore[no-untyped-def]
        import curses

        cursor = 0
        offset = 0
        search = ""
        expanded_groups: set[str] = set()
        force_redraw = True
        with contextlib.suppress(Exception):
            stdscr.idlok(False)
            stdscr.idcok(False)
            stdscr.scrollok(False)
        while True:
            items: list[tuple[str, str, bool, list[str]]] = [(code, self.test_region_line(code), False, []) for code in primary_regions]
            for group_key, labels, group_regions in region_groups:
                label = labels[self.state.lang]
                items.append((f"__group__:{group_key}", self.test_region_group_line(label, group_regions), True, group_regions))
                if group_key in expanded_groups:
                    items.extend((code, "  " + self.test_region_line(code), False, []) for code in group_regions)
            visible = [(key, label, is_group, group_regions) for key, label, is_group, group_regions in items if search.lower() in label.lower()]
            if cursor >= len(visible):
                cursor = max(0, len(visible) - 1)
            h, w = self.draw_header(stdscr, title, hint, clear=False)
            fill_curses_row(stdscr, 2, w, curses.A_NORMAL)
            if search:
                stdscr.addnstr(2, 0, f"/{search}", w - 1)
            self.draw_row(stdscr, 3, self.test_regions_header())
            list_top = 4
            rows = max(0, h - list_top - 1)
            scroll_rows = max(1, rows)
            if cursor < offset:
                offset = cursor
            if cursor >= offset + scroll_rows:
                offset = cursor - scroll_rows + 1
            rendered_rows: list[tuple[str, bool]] = []
            for index, (key, label, is_group, group_regions) in enumerate(visible[offset : offset + scroll_rows], start=offset):
                is_current = index == cursor
                marker = ">" if is_current else " "
                if is_group:
                    group_key = key.split(":", 1)[1]
                    checked = bool(selected & set(group_regions))
                    check = "x" if checked else " "
                    arrow = "-" if group_key in expanded_groups else "+"
                    rendered = f"{marker} [{check}] {arrow} {label}"
                else:
                    check = "x" if key in selected else " "
                    rendered = f"{marker} [{check}]   {label}"
                rendered_rows.append((rendered, is_current))
            self.draw_region_list_window(stdscr, list_top, rows, rendered_rows, force_redraw)
            force_redraw = False
            keypress = stdscr.getch()
            if keypress in (ord("q"), 27):
                raise KeyboardInterrupt
            if self.is_back_key(keypress):
                raise BackRequested
            if keypress in (curses.KEY_UP, ord("k")):
                cursor = max(0, cursor - 1)
            elif keypress in (curses.KEY_DOWN, ord("j")):
                cursor = min(max(0, len(visible) - 1), cursor + 1)
            elif keypress == ord("o"):
                if visible and visible[cursor][2]:
                    group_key = visible[cursor][0].split(":", 1)[1]
                    if group_key in expanded_groups:
                        expanded_groups.remove(group_key)
                    else:
                        expanded_groups.add(group_key)
                    force_redraw = True
            elif keypress == ord("O"):
                all_group_keys = {group_key for group_key, _, _ in region_groups}
                if expanded_groups >= all_group_keys:
                    expanded_groups.clear()
                else:
                    expanded_groups = set(all_group_keys)
                force_redraw = True
            elif keypress == ord(" "):
                if not visible:
                    continue
                key, _, is_group, group_regions = visible[cursor]
                if is_group:
                    group_set = set(group_regions)
                    if selected & group_set:
                        selected.difference_update(group_set)
                    else:
                        selected.update(group_set)
                    continue
                if key in selected:
                    selected.remove(key)
                else:
                    selected.add(key)
            elif keypress == ord("a"):
                for key, _, is_group, group_regions in visible:
                    if is_group:
                        selected.update(group_regions)
                    else:
                        selected.add(key)
            elif keypress == ord("c"):
                for key, _, is_group, group_regions in visible:
                    if is_group:
                        selected.difference_update(group_regions)
                    else:
                        selected.discard(key)
            elif keypress == ord("/"):
                try:
                    search = self.prompt(stdscr, "搜索" if self.state.lang == "zh" else "Search")
                except BackRequested:
                    continue
                cursor = 0
                offset = 0
                force_redraw = True
            elif keypress in (10, 13, curses.KEY_ENTER):
                return selected

    def choose_test_scope(self, stdscr) -> list[Service]:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        services = services_in_test_regions(self.state)
        selected = {service.name for service in services}
        items = [(service.name, self.test_service_line(service)) for service in services]
        title = "选择要检测的平台" if lang == "zh" else "Choose Services To Test"
        hint = (
            "a 全选  c 清空  / 搜索  Space 切换  Enter 开始检测  Ctrl+B 返回"
            if lang == "zh"
            else "a all  c clear  / search  Space toggle  Enter start tests  Ctrl+B back"
        )
        if not items:
            self.message(
                stdscr,
                "所选地区没有匹配平台，Enter 继续或 Ctrl+B 返回重选地区。"
                if lang == "zh"
                else "No services match selected regions. Enter to continue or Ctrl+B to choose regions again.",
            )
            return []
        chosen = set(self.multi_select(stdscr, title, items, selected, hint, self.test_services_header()))
        return [service for service in services if service.name in chosen]

    def run_tests(self, stdscr, services: list[Service]) -> None:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        self.state.tested_services = {service.name for service in services}
        for service in services:
            if not service_has_probe(service):
                service.probe_result = ProbeResult("unknown", detail="no reliable native probe")
        services = [service for service in services if service_has_probe(service)]
        if not services:
            return
        workers = test_worker_count(len(services))
        last_line = ""
        for index, service, result, total in run_probe_batch(
            services,
            timeout=DEFAULT_TEST_TIMEOUT,
            ip_version="auto",
            check_path=self.state.check_path,
        ):
            service.probe_result = result
            last_line = f"{service.name}: {status_label(result.status, lang)}"
            self.draw_header(
                stdscr,
                "正在检测" if lang == "zh" else "Testing",
                "并发检测中；检测结果仅作为建议，不会自动决定分流策略。" if lang == "zh" else "Testing concurrently. Results are advisory; selection remains user-controlled.",
            )
            stdscr.addnstr(3, 0, (f"并发: {workers}  进度: {index}/{total}" if lang == "zh" else f"Workers: {workers}  Progress: {index}/{total}"), 120)
            stdscr.addnstr(5, 0, ("最近完成: " if lang == "zh" else "Last completed: ") + last_line, 160)
            stdscr.refresh()

    def message(self, stdscr, text: str) -> None:  # type: ignore[no-untyped-def]
        h, w = self.draw_header(stdscr, "提示" if self.state.lang == "zh" else "Notice")
        stdscr.addnstr(3, 0, text, w - 1)
        stdscr.refresh()
        key = stdscr.getch()
        if self.is_back_key(key):
            raise BackRequested
        if key in (ord("q"), 27):
            raise KeyboardInterrupt

    def choose_unlock_services(self, stdscr) -> None:  # type: ignore[no-untyped-def]
        import curses

        lang = self.state.lang
        cursor = 0
        offset = 0
        search = ""
        status_filters = ["all", "no", "unknown", "yes", "partial", "error"]
        status_index = 0
        service_region_filters = ["all"] + available_regions(self.state.services)
        service_region_index = 0
        region_filters = ["all"] + sorted(backend_regions(self.state.backends.values()), key=lambda code: region_name(code, lang))
        region_index = 0
        force_redraw = True
        with contextlib.suppress(Exception):
            stdscr.idlok(False)
            stdscr.idcok(False)
            stdscr.scrollok(False)

        while True:
            visible = self.filtered_services(search, status_filters[status_index], service_region_filters[service_region_index], region_filters[region_index])
            if cursor >= len(visible):
                cursor = max(0, len(visible) - 1)
            h, w = self.draw_header(
                stdscr,
                "选择需要 AKDNS 分流的平台" if lang == "zh" else "Choose Services For AKDNS Split",
                (
                    "Space 选择  b 切换backend  f 状态  r 服务区域  g backend地区  s 策略  a 全选可见  c 清空可见  / 搜索  Enter"
                    if lang == "zh"
                    else "Space toggle  b cycle backend  f status  r service region  g backend region  s strategies  a visible  c clear  / search  Enter"
                ),
                clear=False,
            )
            filter_text = self.filter_text(search, status_filters[status_index], service_region_filters[service_region_index], region_filters[region_index])
            fill_curses_row(stdscr, 2, w, curses.A_NORMAL)
            stdscr.addnstr(2, 0, filter_text, w - 1)
            self.draw_row(stdscr, 3, self.unlock_services_header(), False)
            list_top = 4
            detail_row = max(list_top + 1, h - 3)
            rows = max(1, detail_row - list_top)
            if cursor < offset:
                offset = cursor
            if cursor >= offset + rows:
                offset = cursor - rows + 1
            rendered_rows: list[tuple[str, bool]] = []
            for index, service in enumerate(visible[offset : offset + rows], start=offset):
                is_current = index == cursor
                marker = ">" if is_current else " "
                check = "x" if service.selected else " "
                line = f"{marker} [{check}] {self.unlock_service_line(service)}"
                rendered_rows.append((line, is_current))
            if not visible:
                rendered_rows.append(("无匹配项" if lang == "zh" else "No matches", False))
            self.draw_region_list_window(stdscr, list_top, rows, rendered_rows, force_redraw, refresh=False)
            force_redraw = False
            if h > 2:
                self.draw_row(stdscr, h - 2, "")
            if not visible:
                self.draw_row(stdscr, detail_row, "")
            else:
                selected = visible[cursor]
                detail_title = "可用 backend: " if lang == "zh" else "Available backends: "
                detail = detail_title + (self.backends_line(selected, limit=24) or "-")
                self.draw_row(stdscr, detail_row, detail)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("q"), 27):
                raise KeyboardInterrupt
            if self.is_back_key(key):
                raise BackRequested
            if key in (curses.KEY_UP, ord("k")):
                cursor = max(0, cursor - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                cursor = min(max(0, len(visible) - 1), cursor + 1)
            elif key == ord(" "):
                if visible:
                    service = visible[cursor]
                    if service.configurable:
                        service.selected = not service.selected
                        if service.selected and not service.selected_backend:
                            service.selected_backend = choose_default_backend(service, self.state.backends, self.state.backend_preferred_name)
                        if not service.selected:
                            service.selected_backend = None
            elif key == ord("b"):
                if visible:
                    self.cycle_backend(visible[cursor])
            elif key == ord("f"):
                status_index = (status_index + 1) % len(status_filters)
                cursor = 0
                force_redraw = True
            elif key == ord("r"):
                service_region_index = (service_region_index + 1) % len(service_region_filters)
                cursor = 0
                force_redraw = True
            elif key == ord("g"):
                region_index = (region_index + 1) % len(region_filters)
                cursor = 0
                force_redraw = True
            elif key == ord("a"):
                for service in visible:
                    self.select_service(service)
            elif key == ord("c"):
                for service in visible:
                    service.selected = False
                    service.selected_backend = None
            elif key == ord("s"):
                try:
                    self.apply_backend_strategy_dialog(stdscr, visible)
                except BackRequested:
                    continue
                force_redraw = True
            elif key == ord("/"):
                try:
                    search = self.prompt(stdscr, "搜索" if lang == "zh" else "Search")
                except BackRequested:
                    continue
                cursor = 0
                force_redraw = True
            elif key in (10, 13, curses.KEY_ENTER):
                return

    def apply_backend_strategy_dialog(self, stdscr, visible: list[Service]) -> None:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        scopes = [
            (
                label,
                f"{strategy_scope_label(label, lang)} ({count_strategy_scope(services, status_filter, only_unselected)})",
            )
            for label, services, status_filter, only_unselected in strategy_scope_options(self.state.services, visible)
        ]
        scope = self.single_select(
            stdscr,
            "策略作用范围" if lang == "zh" else "Strategy Scope",
            scopes,
            "visible-locked",
            "Enter 选择  Ctrl+B 返回" if lang == "zh" else "Enter choose  Ctrl+B back",
        )
        mode_items = [
            ("backend-strict", "使用偏好 backend；平台不支持则跳过" if lang == "zh" else "Use preferred backend; skip unsupported services"),
            ("backend-fallback", "使用偏好 backend；平台不支持则第一个可用" if lang == "zh" else "Use preferred backend; fallback to first available"),
            ("first", "直接选择第一个可用 backend" if lang == "zh" else "Use first available backend"),
            ("clear", "取消选择这些平台" if lang == "zh" else "Clear selected services in scope"),
        ]
        mode = self.single_select(
            stdscr,
            "backend 选择方式" if lang == "zh" else "Backend Selection Mode",
            mode_items,
            "backend-fallback",
            "Enter 选择  Ctrl+B 返回" if lang == "zh" else "Enter choose  Ctrl+B back",
        )
        target, status_filter, only_unselected = self.strategy_scope(scope, visible)
        if mode == "clear":
            result = clear_strategy_services(target, status_filter, only_unselected)
            self.message(stdscr, strategy_result_text(result, lang))
            return
        preferred_backend = ""
        if mode.startswith("backend"):
            preferred_backend = self.choose_backend_dialog(stdscr)
            if not preferred_backend:
                self.message(stdscr, "未选择 backend，策略未执行。" if lang == "zh" else "No backend selected; strategy was not applied.")
                return
        result = apply_backend_strategy(
            target,
            self.state.backends,
            preferred_backend,
            status_filter=status_filter,
            fallback_first=mode in {"backend-fallback", "first"},
            only_unselected=only_unselected,
        )
        if preferred_backend:
            self.state.backend_preferred_name = preferred_backend
        self.message(stdscr, strategy_result_text(result, lang))

    def strategy_scope(self, scope: str, visible: list[Service]) -> tuple[list[Service], set[str] | None, bool]:
        for label, services, status_filter, only_unselected in strategy_scope_options(self.state.services, visible):
            if label == scope:
                return services, status_filter, only_unselected
        return list(self.state.services), LOCKED_STRATEGY_STATUSES, False

    def choose_backend_dialog(self, stdscr) -> str:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        items = [
            (
                backend.name,
                format_columns(
                    [
                        (backend.name, 28),
                        (region_name(backend_region(backend), lang), 16),
                        (backend_region(backend), 8),
                    ]
                ),
            )
            for backend in sorted(
                self.state.backends.values(),
                key=lambda backend: (region_sort_key(backend_region(backend)), backend.name.lower()),
            )
        ]
        default = self.state.backend_preferred_name if self.state.backend_preferred_name in self.state.backends else (items[0][0] if items else "")
        header = (
            "  " + format_columns([("backend", 28), ("地区", 16), ("代码", 8)])
            if lang == "zh"
            else "  " + format_columns([("Backend", 28), ("Region", 16), ("Code", 8)])
        )
        return self.single_select(
            stdscr,
            "选择本次策略偏好 backend" if lang == "zh" else "Choose Preferred Backend For This Strategy",
            items,
            default,
            "Enter 选择  Ctrl+B 返回" if lang == "zh" else "Enter choose  Ctrl+B back",
            header=header,
        )

    def backend_region_line(self, code: str) -> str:
        lang = self.state.lang
        count = sum(1 for backend in self.state.backends.values() if backend_region(backend) == code)
        if lang == "zh":
            return f"{region_name(code, lang):<12} {code:<4} {count} 个 backend"
        return f"{region_name(code, lang):<20} {code:<4} {count} backends"

    def confirm_and_write(self, stdscr) -> WizardResult:  # type: ignore[no-untyped-def]
        import curses

        lang = self.state.lang
        offset = 0
        while True:
            lines = report_summary_lines(self.state) if self.state.mode == "test-only" else final_preview_lines(self.state)
            h, w = self.draw_header(
                stdscr,
                "最终确认" if lang == "zh" else "Final Confirmation",
                (
                    "↑↓ 滚动  o 修改文件名  s 保存  Ctrl+B 返回  q 不保存退出"
                    if lang == "zh"
                    else "↑↓ scroll  o edit file names  s save  Ctrl+B back  q exit without saving"
                ),
            )
            if self.state.mode == "test-only":
                visible_rows = max(1, h - 5)
                if offset > max(0, len(lines) - visible_rows):
                    offset = max(0, len(lines) - visible_rows)
                for row, line in enumerate(lines[offset : offset + visible_rows], start=3):
                    self.draw_row(stdscr, row, line)
                stdscr.addnstr(h - 2, 0, "Enter 退出  Ctrl+B 返回  ↑↓ 滚动" if lang == "zh" else "Enter exit  Ctrl+B back  ↑↓ scroll", w - 1)
                stdscr.refresh()
                key = stdscr.getch()
                if self.is_back_key(key):
                    raise BackRequested
                if key in (curses.KEY_UP, ord("k")):
                    offset = max(0, offset - 1)
                    continue
                if key in (curses.KEY_DOWN, ord("j")):
                    offset = min(max(0, len(lines) - 1), offset + 1)
                    continue
                return WizardResult(displayed_only=True)

            visible_rows = max(1, h - 5)
            if offset > max(0, len(lines) - visible_rows):
                offset = max(0, len(lines) - visible_rows)
            for row, line in enumerate(lines[offset : offset + visible_rows], start=3):
                self.draw_row(stdscr, row, line)
            if len(lines) > visible_rows:
                marker = f"{offset + 1}-{min(len(lines), offset + visible_rows)}/{len(lines)}"
                stdscr.addnstr(2, max(0, w - len(marker) - 1), marker, len(marker))
            stdscr.refresh()
            key = stdscr.getch()
            if self.is_back_key(key):
                raise BackRequested
            if key in (curses.KEY_UP, ord("k")):
                offset = max(0, offset - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                offset = min(max(0, len(lines) - 1), offset + 1)
            elif key == ord("o"):
                self.ask_output_paths(stdscr)
                offset = 0
            elif key == ord("s"):
                paths = output_paths(self.state)
                rules = make_rules_json(self.state.services)
                smartdns = make_smartdns_conf(self.state)
                paths["rules"].write_text(rules, encoding="utf-8")
                paths["smartdns"].write_text(smartdns, encoding="utf-8")
                return WizardResult(wrote_files=True)
            if key in (ord("q"), 27):
                return WizardResult()

    def ask_output_paths(self, stdscr) -> dict[str, Path]:  # type: ignore[no-untyped-def]
        lang = self.state.lang
        output_dir = Path.cwd()
        paths = output_paths(self.state)
        wanted = ["rules", "smartdns"]
        for key in wanted:
            default = paths[key]
            try:
                raw = self.prompt(
                    stdscr,
                    (
                        f"{DEFAULT_OUTPUT_FILES[key]} 保存路径，留空保留 {default}，Ctrl+B 返回"
                        if lang == "zh"
                        else f"{DEFAULT_OUTPUT_FILES[key]} output path, empty keeps {default}, Ctrl+B back"
                    ),
                )
            except BackRequested:
                return {}
            path = Path(raw.strip()) if raw.strip() else default
            if not path.is_absolute():
                path = output_dir / path
            paths[key] = path
        self.state.output_paths = paths
        return paths

    def multi_select(
        self,
        stdscr,
        title: str,
        items: list[tuple[str, str]],
        selected: set[str],
        hint: str,
        header: str = "",
    ) -> set[str]:  # type: ignore[no-untyped-def]
        import curses

        cursor = 0
        offset = 0
        search = ""
        while True:
            visible = [(key, label) for key, label in items if search.lower() in label.lower()]
            if cursor >= len(visible):
                cursor = max(0, len(visible) - 1)
            h, w = self.draw_header(stdscr, title, hint)
            if search:
                stdscr.addnstr(2, 0, f"/{search}", w - 1)
            start_row = 4 if header else 3
            if header:
                self.draw_row(stdscr, 3, header)
            rows = max(1, h - start_row - 1)
            if cursor < offset:
                offset = cursor
            if cursor >= offset + rows:
                offset = cursor - rows + 1
            self.clear_rows(stdscr, start_row, rows)
            for row, (key, label) in enumerate(visible[offset : offset + rows], start=start_row):
                marker = ">" if (offset + row - start_row) == cursor else " "
                check = "x" if key in selected else " "
                self.draw_row(stdscr, row, f"{marker} [{check}] {label}", marker == ">")
            stdscr.refresh()
            keypress = stdscr.getch()
            if keypress in (ord("q"), 27):
                raise KeyboardInterrupt
            if self.is_back_key(keypress):
                raise BackRequested
            if keypress in (curses.KEY_UP, ord("k")):
                cursor = max(0, cursor - 1)
            elif keypress in (curses.KEY_DOWN, ord("j")):
                cursor = min(max(0, len(visible) - 1), cursor + 1)
            elif keypress == ord(" "):
                if visible:
                    key = visible[cursor][0]
                    if key in selected:
                        selected.remove(key)
                    else:
                        selected.add(key)
            elif keypress == ord("a"):
                selected.update(key for key, _ in visible)
            elif keypress == ord("c"):
                for key, _ in visible:
                    selected.discard(key)
            elif keypress == ord("/"):
                try:
                    search = self.prompt(stdscr, "搜索" if self.state.lang == "zh" else "Search")
                except BackRequested:
                    continue
                cursor = 0
            elif keypress in (10, 13, curses.KEY_ENTER):
                return selected

    def single_select(
        self,
        stdscr,
        title: str,
        items: list[tuple[str, str]],
        default: str,
        hint: str,
        header: str = "",
        allow_back: bool = True,
    ) -> str:  # type: ignore[no-untyped-def]
        import curses

        cursor = next((index for index, (key, _) in enumerate(items) if key == default), 0)
        offset = 0
        while True:
            h, w = self.draw_header(stdscr, title, hint)
            start_row = 4 if header else 3
            if header:
                self.draw_row(stdscr, 3, header)
            rows = max(1, h - start_row - 1)
            if cursor < offset:
                offset = cursor
            if cursor >= offset + rows:
                offset = cursor - rows + 1
            self.clear_rows(stdscr, start_row, rows)
            for row, (key, label) in enumerate(items[offset : offset + rows], start=start_row):
                index = offset + row - start_row
                marker = ">" if index == cursor else " "
                self.draw_row(stdscr, row, f"{marker} {label}", marker == ">")
            if len(items) > rows:
                marker = f"{offset + 1}-{min(len(items), offset + rows)}/{len(items)}"
                stdscr.addnstr(2, max(0, w - len(marker) - 1), marker, len(marker))
            stdscr.refresh()
            keypress = stdscr.getch()
            if keypress in (ord("q"), 27):
                raise KeyboardInterrupt
            if allow_back and self.is_back_key(keypress):
                raise BackRequested
            if keypress in (curses.KEY_UP, ord("k")):
                cursor = max(0, cursor - 1)
            elif keypress in (curses.KEY_DOWN, ord("j")):
                cursor = min(len(items) - 1, cursor + 1)
            elif keypress in (10, 13, curses.KEY_ENTER):
                return items[cursor][0]

    def prompt(self, stdscr, label: str) -> str:  # type: ignore[no-untyped-def]
        import curses

        h, w = stdscr.getmaxyx()
        curses.curs_set(1)
        prefix = f"{label}: "
        value: list[str] = []
        max_len = max(1, w - len(prefix) - 3)
        try:
            while True:
                stdscr.addnstr(h - 2, 0, " " * (w - 1), w - 1)
                stdscr.addnstr(h - 2, 0, prefix + "".join(value)[-max_len:], w - 1)
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord("q"), 27):
                    raise KeyboardInterrupt
                if self.is_back_key(key):
                    raise BackRequested
                if self.is_delete_key(key):
                    if value:
                        value.pop()
                    continue
                if key in (10, 13, curses.KEY_ENTER):
                    return "".join(value).strip()
                if 32 <= key <= 126:
                    value.append(chr(key))
        finally:
            curses.curs_set(0)

    def service_line(self, service: Service, show_backend: bool) -> str:
        lang = self.state.lang
        result = service.probe_result
        status = status_label(result.status, lang)
        region = region_name(result.region, lang) if result.region else "-"
        regions = self.compact_regions(service.region_hints, limit=3)
        capabilities = self.capability_labels(service)
        service_region_label = "服务区域" if lang == "zh" else "service"
        detected_region_label = "检测区域" if lang == "zh" else "detected"
        name_col = pad_or_ellipsize_display_cells(service.name, 28)
        status_col = pad_or_ellipsize_display_cells(status, 8)
        service_col = pad_or_ellipsize_display_cells(f"{service_region_label}:{regions}", 34 if lang == "zh" else 38)
        detected_col = pad_or_ellipsize_display_cells(f"{detected_region_label}:{region}", 16 if lang == "zh" else 20)
        line = f"{name_col}{status_col}{service_col}{detected_col}{' '.join(capabilities)}"
        if show_backend:
            backend = self.state.backends.get(service.selected_backend or "") if service.selected else None
            line += f"  -> {format_backend(backend, lang)}  {self.backend_summary(service)}"
        return line

    def unlock_services_header(self) -> str:
        lang = self.state.lang
        if lang == "zh":
            cols = [
                pad_or_ellipsize_display_cells("平台", 26),
                pad_or_ellipsize_display_cells("状态", 8),
                pad_or_ellipsize_display_cells("服务区域", 36),
                pad_or_ellipsize_display_cells("检测区域", 14),
                pad_or_ellipsize_display_cells("选择backend", 18),
                "支持backend",
            ]
        else:
            cols = [
                pad_or_ellipsize_display_cells("Service", 26),
                pad_or_ellipsize_display_cells("Status", 10),
                pad_or_ellipsize_display_cells("Regions", 40),
                pad_or_ellipsize_display_cells("Detected", 16),
                pad_or_ellipsize_display_cells("Backend", 20),
                "Supported",
            ]
        return "      " + "".join(cols)

    def unlock_service_line(self, service: Service) -> str:
        lang = self.state.lang
        result = service.probe_result
        status = status_label(result.status, lang)
        detected = region_name(result.region, lang) if result.region else "-"
        regions = self.compact_regions(service.region_hints, limit=4)
        backend = format_backend(self.state.backends.get(service.selected_backend or ""), lang) if service.selected else "-"
        supported = self.backend_summary(service)
        if lang == "zh":
            cols = [
                pad_or_ellipsize_display_cells(service.name, 26),
                pad_or_ellipsize_display_cells(status, 8),
                pad_or_ellipsize_display_cells(regions, 36),
                pad_or_ellipsize_display_cells(detected, 14),
                pad_or_ellipsize_display_cells(backend, 18),
                supported,
            ]
        else:
            cols = [
                pad_or_ellipsize_display_cells(service.name, 26),
                pad_or_ellipsize_display_cells(status, 10),
                pad_or_ellipsize_display_cells(regions, 40),
                pad_or_ellipsize_display_cells(detected, 16),
                pad_or_ellipsize_display_cells(backend, 20),
                supported,
            ]
        return "".join(cols)

    def test_service_line(self, service: Service) -> str:
        lang = self.state.lang
        regions = self.compact_regions(service.region_hints, limit=4)
        capabilities = self.capability_labels(service)
        service_region_label = "服务区域" if lang == "zh" else "service"
        name_col = pad_or_ellipsize_display_cells(service.name, 34)
        region_col = pad_or_ellipsize_display_cells(f"{service_region_label}:{regions}", 44 if lang == "zh" else 48)
        return f"{name_col}{region_col}{' '.join(capabilities)}"

    def test_services_header(self) -> str:
        lang = self.state.lang
        if lang == "zh":
            return "      " + "".join(
                [
                    pad_or_ellipsize_display_cells("平台", 34),
                    pad_or_ellipsize_display_cells("服务区域", 44),
                    "能力",
                ]
            )
        return "      " + "".join(
            [
                pad_or_ellipsize_display_cells("Service", 34),
                pad_or_ellipsize_display_cells("Service region", 48),
                "Capabilities",
            ]
        )

    def compact_regions(self, regions: Iterable[str], limit: int = 3) -> str:
        return format_region_list(regions, self.state.lang, limit=limit)

    def capability_labels(self, service: Service) -> list[str]:
        lang = self.state.lang
        labels = []
        if service.configurable:
            labels.append(TEXT[lang]["catalog"])
        if service_has_probe(service):
            labels.append("可检测" if lang == "zh" else "testable")
        else:
            labels.append(TEXT[lang]["no_detector"])
        return labels

    def backend_summary(self, service: Service) -> str:
        candidates = candidate_backends(service, self.state.backends)
        if not candidates:
            return "backends:0"
        regions = sorted({backend_region(backend) for backend in candidates}, key=region_sort_key)
        labels = format_region_list(regions, self.state.lang, limit=4)
        return f"backends:{len(candidates)} [{labels}]"

    def backends_line(self, service: Service, limit: int = 8) -> str:
        candidates = candidate_backends(service, self.state.backends)
        labels = [format_backend(backend, self.state.lang) for backend in candidates[:limit]]
        if len(candidates) > limit:
            labels.append(f"+{len(candidates) - limit}")
        return ", ".join(labels)

    def filtered_services(self, search: str, status_filter: str, service_region_filter: str, region_filter: str) -> list[Service]:
        return filter_services(self.state.services, self.state.backends, search, status_filter, service_region_filter, region_filter)

    def filter_text(self, search: str, status_filter: str, service_region_filter: str, region_filter: str) -> str:
        selected = sum(1 for service in self.state.services if service.selected)
        return filter_summary_text(self.state.lang, search, status_filter, service_region_filter, region_filter, selected)

    def select_service(self, service: Service) -> None:
        if not service.configurable:
            return
        service.selected = True
        if not service.selected_backend:
            service.selected_backend = choose_default_backend(service, self.state.backends, self.state.backend_preferred_name)

    def cycle_backend(self, service: Service) -> None:
        candidates = candidate_backends(service, self.state.backends)
        if not candidates:
            return
        names = [backend.name for backend in candidates]
        if service.selected_backend not in names:
            service.selected_backend = choose_default_backend(service, self.state.backends, self.state.backend_preferred_name)
            return
        index = (names.index(service.selected_backend) + 1) % len(names)
        service.selected_backend = names[index]
        service.selected = True


def fallback_input(prompt: str, allow_back: bool = True) -> str:
    try:
        value = input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt
    if allow_back and value.lower() in {"b", "back"}:
        raise BackRequested
    return value


def run_fallback_ui(state: WizardState) -> WizardResult:
    lang = state.lang
    print(f"{APP_NAME} {VERSION}")
    print("curses is unavailable; using a simple text survey." if lang == "en" else "当前环境不支持 curses，使用简化文本问卷。")
    print("输入 back 或 b 返回上一步。" if lang == "zh" else "Enter back or b to return to the previous step.")
    step = "mode"
    while True:
        try:
            if step == "mode":
                print("\n" + ("流程: 1=检测后生成, 2=只测试解锁, 3=只生成配置" if lang == "zh" else "Workflow: 1=test then generate, 2=test only, 3=generate only"))
                mode = fallback_input("> ", allow_back=False)
                state.mode = {"1": "test-and-generate", "2": "test-only", "3": "generate-only"}.get(mode, "test-and-generate")
                step = "dns"
            elif step == "dns":
                print("\n" + ("公共 DNS 可选: cloudflare, google, quad9, adguard, custom" if lang == "zh" else "Public DNS options: cloudflare, google, quad9, adguard, custom"))
                profile = fallback_input("> ").lower()
                if profile in PUBLIC_DNS_PROFILES:
                    state.dns_profile = profile
                if state.dns_profile == "custom":
                    raw = fallback_input("自定义公共 DNS，逗号分隔: " if lang == "zh" else "Custom public DNS, comma separated: ")
                    state.public_dns_servers = parse_dns_servers(raw) or list(PUBLIC_DNS_PROFILES["cloudflare"]["servers"])
                else:
                    state.public_dns_servers = list(PUBLIC_DNS_PROFILES[state.dns_profile]["servers"])
                step = "akdns"
            elif step == "akdns":
                raw = fallback_input("自定义解锁 DNS，留空使用脚本默认: " if lang == "zh" else "Custom unlock DNS, empty for configured default: ")
                state.akdns_servers = parse_dns_servers(raw) or state.akdns_servers
                step = "test-regions" if state.mode in {"test-only", "test-and-generate"} else "services"
            elif step == "test-regions":
                choose_fallback_test_regions(state)
                step = "tests"
            elif step == "tests":
                run_fallback_tests(state)
                step = "summary" if state.mode == "test-only" else "services"
            elif step == "summary":
                print("")
                for line in report_summary_lines(state):
                    print(line)
                raw = fallback_input("Enter 退出，back 返回: " if lang == "zh" else "Enter exit, back to return: ")
                if raw == "":
                    return WizardResult(displayed_only=True)
            elif step == "services":
                choose_fallback_services(state)
                step = "write"
            elif step == "write":
                return ask_and_write_fallback(state)
        except BackRequested:
            step = fallback_previous_step(state, step)


def fallback_previous_step(state: WizardState, step: str) -> str:
    if step == "dns":
        return "mode"
    if step == "akdns":
        return "dns"
    if step == "test-regions":
        return "akdns"
    if step == "tests":
        return "test-regions"
    if step == "summary":
        return "tests"
    if step == "services":
        return "tests" if state.mode in {"test-only", "test-and-generate"} else "akdns"
    if step == "write":
        return "services"
    return step


def run_fallback_tests(state: WizardState) -> None:
    lang = state.lang
    scoped = services_in_test_regions(state)
    state.tested_services = {service.name for service in scoped}
    for service in scoped:
        if not service_has_probe(service):
            service.probe_result = ProbeResult("unknown", detail="no reliable native probe")
    testable = [service for service in scoped if service_has_probe(service)]
    print("\n" + (f"检测范围 {len(scoped)} 个平台，其中 {len(testable)} 个有检测器。" if lang == "zh" else f"Test scope has {len(scoped)} services; {len(testable)} have unlock probes."))
    workers = test_worker_count(len(testable))
    print("\n" + (f"开始并发检测 {len(testable)} 个平台，并发 {workers}..." if lang == "zh" else f"Testing {len(testable)} services with {workers} workers..."))
    for index, service, result, total in run_probe_batch(
        testable,
        timeout=DEFAULT_TEST_TIMEOUT,
        ip_version="auto",
        check_path=state.check_path,
    ):
        service.probe_result = result
        print(f"[{index}/{total}] {service.name}: {status_label(result.status, lang)}")


def choose_fallback_test_regions(state: WizardState) -> None:
    lang = state.lang
    regions = available_regions(state.services)
    primary_regions, region_groups = split_test_regions(regions)
    print("\n" + ("选择要检测的平台地区。" if lang == "zh" else "Choose regions to test."))
    print(
        (
            "顶级只显示核心地区；也可输入分组名选择整组，例如 europe、southeast-asia。"
            if lang == "zh"
            else "Top-level shows core regions only; enter a group key such as europe or southeast-asia to select the whole group."
        )
    )
    for code in primary_regions:
        total, native = region_service_counts(state.services, code)
        if lang == "zh":
            print(f"  {code}  {region_name(code, lang)}  {total} 平台 / {native} 可检测")
        else:
            print(f"  {code}  {region_name(code, lang)}  {total} services / {native} testable")
    for group_key, labels, group_regions in region_groups:
        label = labels[lang]
        total, native = region_group_counts(state.services, group_regions)
        if lang == "zh":
            print(f"  {group_key}  {label}  {total} 平台 / {native} 可检测")
        else:
            print(f"  {group_key}  {label}  {total} services / {native} testable")
        for code in group_regions:
            total, native = region_service_counts(state.services, code)
            if lang == "zh":
                print(f"    {code}  {region_name(code, lang)}  {total} 平台 / {native} 可检测")
            else:
                print(f"    {code}  {region_name(code, lang)}  {total} services / {native} testable")
    raw = fallback_input("检测区域，逗号分隔，留空表示全部: " if lang == "zh" else "Test regions, comma separated, empty for all: ")
    valid = set(regions)
    tokens = {item.strip().lower() for item in raw.split(",") if item.strip()}
    selected = {normalize_region_input(item) for item in raw.split(",") if normalize_region_input(item) in valid}
    for group_key, labels, group_regions in region_groups:
        if group_key.lower() in tokens or labels["en"].lower() in tokens or labels["zh"].lower() in tokens:
            selected.update(group_regions)
    state.test_regions = selected


def choose_fallback_services(state: WizardState) -> None:
    lang = state.lang
    search = ""
    status_filter = "all"
    service_region_filter = "all"
    region_filter = "all"
    while True:
        visible = fallback_filtered_services(state, search, status_filter, service_region_filter, region_filter)
        print("")
        print("选择需要 AKDNS 分流的平台" if lang == "zh" else "Choose services for AKDNS split")
        print(fallback_filter_text(state, search, status_filter, service_region_filter, region_filter, len(visible)))
        for service in visible[:25]:
            print(f"  {fallback_service_line(state, service)}")
        if len(visible) > 25:
            print(f"  ... {len(visible) - 25} more")
        print("")
        print(
            (
                "操作: s=批量策略, a=选择可见, c=清空可见, f=状态筛选, r=服务区域筛选, g=backend地区筛选, /=搜索, n=下一步, back=返回"
            )
            if lang == "zh"
            else "Actions: s=strategy, a=select visible, c=clear visible, f=status filter, r=service-region filter, g=backend-region filter, /=search, n=next, back=return"
        )
        action = fallback_input("> ").lower()
        if action in {"n", ""}:
            return
        if action == "s":
            try:
                choose_fallback_backend_strategy(state, visible)
            except BackRequested:
                continue
            continue
        if action == "a":
            for service in visible:
                select_service_with_default(state, service)
            continue
        if action == "c":
            for service in visible:
                service.selected = False
                service.selected_backend = None
            continue
        if action == "f":
            try:
                status_filter = choose_fallback_status_filter(state, status_filter)
            except BackRequested:
                continue
            continue
        if action == "r":
            try:
                service_region_filter = choose_fallback_service_region_filter(state, service_region_filter)
            except BackRequested:
                continue
            continue
        if action == "g":
            try:
                region_filter = choose_fallback_backend_region_filter(state, region_filter)
            except BackRequested:
                continue
            continue
        if action == "/":
            try:
                search = fallback_input("搜索关键词，留空清除: " if lang == "zh" else "Search text, empty to clear: ")
            except BackRequested:
                continue
            continue


def fallback_filtered_services(state: WizardState, search: str, status_filter: str, service_region_filter: str, region_filter: str) -> list[Service]:
    return filter_services(state.services, state.backends, search, status_filter, service_region_filter, region_filter)


def fallback_filter_text(state: WizardState, search: str, status_filter: str, service_region_filter: str, region_filter: str, visible_count: int) -> str:
    selected = sum(1 for service in state.services if service.selected)
    return filter_summary_text(state.lang, search, status_filter, service_region_filter, region_filter, selected, visible_count)


def fallback_service_line(state: WizardState, service: Service) -> str:
    lang = state.lang
    mark = "x" if service.selected else " "
    status = status_label(service.probe_result.status, lang)
    backend = format_backend(state.backends.get(service.selected_backend or ""), lang) if service.selected else "-"
    supported = ", ".join(format_backend(backend, lang) for backend in candidate_backends(service, state.backends)[:6])
    return f"[{mark}] {service.name}  {status}  -> {backend}  backends: {supported}"


def choose_fallback_status_filter(state: WizardState, current: str) -> str:
    lang = state.lang
    values = ["all", "no", "unknown", "yes", "partial", "error"]
    print(", ".join(f"{value}={TEXT[lang]['status_all'] if value == 'all' else status_label(value, lang)}" for value in values))
    raw = fallback_input("状态筛选: " if lang == "zh" else "Status filter: ").lower()
    return raw if raw in values else current


def choose_fallback_service_region_filter(state: WizardState, current: str) -> str:
    lang = state.lang
    regions = available_regions(state.services)
    print(", ".join(["all"] + [f"{code}={region_name(code, lang)}" for code in regions]))
    raw = normalize_region_input(fallback_input("服务区域筛选: " if lang == "zh" else "Service-region filter: "))
    return raw if raw in set(regions) else ("all" if raw == "ALL" else current)


def choose_fallback_backend_region_filter(state: WizardState, current: str) -> str:
    lang = state.lang
    regions = sorted(backend_regions(state.backends.values()), key=region_sort_key)
    print(", ".join(["all"] + [f"{code}={region_name(code, lang)}" for code in regions]))
    raw = normalize_region_input(fallback_input("backend 地区筛选: " if lang == "zh" else "Backend-region filter: "))
    return raw if raw in set(regions) else ("all" if raw == "ALL" else current)


def choose_fallback_backend_strategy(state: WizardState, visible: list[Service]) -> None:
    lang = state.lang
    scopes = {
        str(index): option
        for index, option in enumerate(strategy_scope_options(state.services, visible), start=1)
    }
    print("")
    print("策略作用范围:" if lang == "zh" else "Strategy scope:")
    for key, (label, services, status_filter, only_unselected) in scopes.items():
        count = count_strategy_scope(services, status_filter, only_unselected)
        text = strategy_scope_label(label, lang)
        print(f"  {key}. {text} ({count})")
    scope_key = fallback_input("> ")
    if scope_key not in scopes:
        return
    _, target, status_filter, only_unselected = scopes[scope_key]
    modes = {
        "1": "backend-strict",
        "2": "backend-fallback",
        "3": "first",
        "4": "clear",
    }
    print("")
    print("backend 选择方式:" if lang == "zh" else "Backend selection mode:")
    print("  1. 使用偏好 backend；平台不支持则跳过" if lang == "zh" else "  1. Use preferred backend; skip unsupported services")
    print("  2. 使用偏好 backend；平台不支持则第一个可用" if lang == "zh" else "  2. Use preferred backend; fallback to first available")
    print("  3. 直接选择第一个可用 backend" if lang == "zh" else "  3. Use first available backend")
    print("  4. 取消选择这些平台" if lang == "zh" else "  4. Clear selected services in scope")
    mode = modes.get(fallback_input("> "), "backend-fallback")
    if mode == "clear":
        result = clear_strategy_services(target, status_filter, only_unselected)
        print(strategy_result_text(result, lang))
        return
    preferred_backend = ""
    if mode.startswith("backend"):
        preferred_backend = choose_fallback_backend(state)
        if not preferred_backend:
            print("未选择 backend，策略未执行。" if lang == "zh" else "No backend selected; strategy was not applied.")
            return
    result = apply_backend_strategy(
        target,
        state.backends,
        preferred_backend,
        status_filter=status_filter,
        fallback_first=mode in {"backend-fallback", "first"},
        only_unselected=only_unselected,
    )
    if preferred_backend:
        state.backend_preferred_name = preferred_backend
    print(strategy_result_text(result, lang))


def choose_fallback_backend(state: WizardState) -> str:
    lang = state.lang
    backends = sorted(state.backends.values(), key=lambda backend: (region_sort_key(backend_region(backend)), format_backend(backend, lang)))
    print("")
    print("可用 backend:" if lang == "zh" else "Available backends:")
    for index, backend in enumerate(backends, start=1):
        print(f"  {index}. {format_backend(backend, lang)}  {backend_region(backend)}")
    default = state.backend_preferred_name or (backends[0].name if backends else "")
    raw = fallback_input(
        f"偏好 backend，输入序号或名称，留空使用 {format_backend(state.backends.get(default), lang)}: "
        if lang == "zh"
        else f"Preferred backend, index or name, empty uses {format_backend(state.backends.get(default), lang)}: "
    )
    value = raw.strip() or default
    if value.isdigit():
        index = int(value)
        return backends[index - 1].name if 1 <= index <= len(backends) else ""
    normalized = normalize_name(value)
    for backend in backends:
        if normalize_name(backend.name) == normalized or normalize_name(format_backend(backend, lang)) == normalized:
            return backend.name
    return ""


def select_service_with_default(state: WizardState, service: Service) -> None:
    if not service.configurable:
        return
    service.selected = True
    if not service.selected_backend:
        service.selected_backend = choose_default_backend(service, state.backends, state.backend_preferred_name)


def ask_and_write_fallback(state: WizardState) -> WizardResult:
    lang = state.lang
    while True:
        print("")
        for line in final_preview_lines(state, limit=40):
            print(line)
        print("")
        action = fallback_input(
            "操作: s=保存, o=修改文件名, back=返回, q=退出不保存: "
            if lang == "zh"
            else "Action: s=save, o=edit file names, back=return, q=exit without saving: "
        ).lower()
        if action == "s":
            paths = output_paths(state)
            paths["rules"].write_text(make_rules_json(state.services), encoding="utf-8")
            paths["smartdns"].write_text(make_smartdns_conf(state), encoding="utf-8")
            return WizardResult(wrote_files=True)
        if action == "o":
            try:
                ask_output_paths_fallback(state)
            except BackRequested:
                continue
            continue
        if action == "q":
            return WizardResult()


def ask_output_paths_fallback(state: WizardState) -> None:
    lang = state.lang
    paths = output_paths(state)
    updated: dict[str, Path] = {}
    for key in ["rules", "smartdns"]:
        current = paths[key]
        raw = fallback_input(
            (
                f"{DEFAULT_OUTPUT_FILES[key]} 保存路径，留空保留 {current}: "
                if lang == "zh"
                else f"{DEFAULT_OUTPUT_FILES[key]} output path, empty keeps {current}: "
            )
        )
        path = Path(raw) if raw else current
        updated[key] = path if path.is_absolute() else Path.cwd() / path
    state.output_paths = updated


def list_services(state: WizardState) -> None:
    lang = state.lang
    for service in state.services:
        regions = format_region_list(service.region_hints, lang)
        source = []
        if service.source_catalog:
            source.append("catalog")
        if service.source_check:
            source.append("check.sh")
        probe = probe_source_label(service)
        print(f"{service.name}\tregions={regions}\tsource={'+'.join(source)}\tprobe={probe}")


def refresh_default_backends(state: WizardState) -> None:
    for service in state.services:
        if service.configurable and service.selected and not service.selected_backend:
            service.selected_backend = choose_default_backend(service, state.backends, state.backend_preferred_name)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive AKDNS rule and SmartDNS configuration wizard")
    parser.add_argument("--root", default=".", help="directory containing catalog.json and optional check.sh")
    parser.add_argument("--catalog-url", default=DEFAULT_CATALOG_URL, help="catalog.json URL; empty falls back to local catalog.json")
    parser.add_argument("--check-url", default=DEFAULT_CHECK_URL, help="check.sh URL; empty falls back to local check.sh")
    parser.add_argument("--lang", choices=["zh", "en"], default=None, help="UI language")
    parser.add_argument("--list", action="store_true", help="list merged catalog/check.sh service inventory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root).resolve()
    lang = args.lang or detect_language()

    with tempfile.TemporaryDirectory(prefix="akdns-wizard-") as tmp:
        temp_dir = Path(tmp)
        try:
            catalog = fetch_catalog(args.catalog_url, root / CATALOG_FILE, temp_dir)
        except Exception as exc:
            print(f"Failed to load catalog: {exc}", file=sys.stderr)
            return 2
        try:
            check_path = fetch_check_script(args.check_url, root / CHECK_FILE, temp_dir)
        except Exception as exc:
            print(f"Failed to load check.sh: {exc}", file=sys.stderr)
            return 2
        backends, services = build_services(root, catalog, check_path)
        state = WizardState(lang=lang, services=services, backends=backends, temp_dir=temp_dir, check_path=check_path)
        if args.list:
            list_services(state)
            return 0

        try:
            result = CursesUI(state).run() if terminal_supports_curses() else run_fallback_ui(state)
        except KeyboardInterrupt:
            print("\n" + ("已退出；没有写入工作目录。" if lang == "zh" else "Exited; workspace was not modified."))
            return 130
    if result.wrote_files:
        print("已保存文件" if lang == "zh" else "Saved files")
    elif result.displayed_only:
        print("检测结果已显示；没有写入工作目录。" if lang == "zh" else "Test results displayed; workspace was not modified.")
    else:
        print(TEXT[lang]["write_skipped"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

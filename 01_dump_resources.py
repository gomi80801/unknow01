#!/usr/bin/env python3
"""
01_dump_resources.py — Xuất setting toàn bộ resource GCP ra 1 file JSON cho mỗi service.
Phục vụ tạo parameter sheet (Excel) từ các file JSON này.

Service + file output (thứ tự theo yêu cầu):
  01_vpc.json                  VPC
  02_subnet.json               Subnet
  03_firewall.json             Firewall
  04_cloud_armor.json          Cloud Armor
  05_certificate_manager.json  Cloud Certificate Manager
  06_load_balancer.json        Load Balancer (address, forwarding rule, target proxy,
                               url map, backend service, health check, NEG,
                               path_matchers = Path matcher của ALB)
  07_cloud_run.json            Cloud Run (Service & Job)
  08_cloud_storage.json        Cloud Storage
  09_vm.json                   VM (Compute Engine)
  10_spanner.json              Cloud Spanner
  11_redis.json                Memorystore (Redis)
  12_dedicated_interconnect.json  Dedicated Interconnect (connection + VLAN attachment)
  13_ha_vpn.json               Cloud HA VPN (gateway, tunnel, external gateway)
  14_cloud_router.json         Cloud Router

Sử dụng:
  ./01_dump_resources.py --project <PROJECT_ID>
  ./01_dump_resources.py --project <ID> --regions asia-northeast1,asia-northeast2
  ./01_dump_resources.py --project <ID> --only vpc,load_balancer

Cấu trúc mỗi file JSON:
  { service, api, project, generated_at, regions, count, count_all, errors,
    groups: { <nhóm>: [ resource JSON đầy đủ (describe) ] } }

Chỉ đọc (list/describe) — không tạo/sửa/xóa gì.
Secret được redact trước khi ghi file (--no-redact để tắt).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from string import Formatter

VERSION = "1.0"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"
# Tokyo & Osaka
DEFAULT_REGIONS = "asia-northeast1,asia-northeast2"

# ---------------------------------------------------------------------------
# Redact — không để secret lọt vào file JSON (rule bảo mật toàn cục)
# ---------------------------------------------------------------------------

SECRET_KEY_RE = re.compile(
    r"(pass(word|wd)?|secret|token|api[-_]?key|apikey|private[-_]?key|"
    r"credential|connection[-_]?string|conn[-_]?str|shared[-_]?secret|client[-_]?key|"
    r"auth[-_]?key)", re.IGNORECASE)
VALUE_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----"),
     "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "[REDACTED-API-KEY]"),
    (re.compile(r"ya29\.[0-9A-Za-z_\-\.]+"), "[REDACTED-TOKEN]"),
]
PAIR_RE = re.compile(
    r"(\"[^\"]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"credential|shared[_-]?secret)[^\"]*\"\s*:\s*)(\"(?:[^\"\\]|\\.)*\")",
    re.IGNORECASE)
ENV_PAIR_RE = re.compile(
    r"(\{\s*\"name\"\s*:\s*\"[^\"]*(?:password|passwd|secret|token|apikey|api[_-]?key|"
    r"private[_-]?key|credential)[^\"]*\"\s*,\s*\"value\"\s*:\s*)"
    r"(\"(?:[^\"\\]|\\.)*\")", re.IGNORECASE)


def redact_text(s: str) -> str:
    if not isinstance(s, str) or not s:
        return s
    out = PAIR_RE.sub(r'\1"[REDACTED]"', s)
    out = ENV_PAIR_RE.sub(r'\1"[REDACTED]"', out)
    for pat, repl in VALUE_PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_obj(obj):
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if isinstance(k, str) and SECRET_KEY_RE.search(k)
                    else redact_obj(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


# ---------------------------------------------------------------------------
# gcloud
# ---------------------------------------------------------------------------

def gcloud_env(project: str) -> dict:
    env = os.environ.copy()
    env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"   # không hỏi "enable API?" → tránh treo
    if project:
        env["CLOUDSDK_CORE_PROJECT"] = project
    return env


def run_gcloud(tokens: list[str], project: str, timeout: int = 180):
    """Trả về (data, None) OK — data: list/dict JSON; (None, err) nếu lỗi."""
    cmd = ["gcloud", *tokens, "--format=json"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=gcloud_env(project))
    except subprocess.TimeoutExpired:
        return None, f"timeout {timeout}s: {' '.join(cmd[:6])}"
    except FileNotFoundError:
        return None, "không tìm thấy binary gcloud"
    if p.returncode != 0:
        err = (p.stderr or "").strip() or (p.stdout or "").strip()
        return None, redact_text(err[:800])
    txt = (p.stdout or "").strip()
    if not txt:
        return [], None
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return None, f"stdout không phải JSON: {txt[:200]}"


def resolve_project(cli_project: str | None) -> str:
    if cli_project:
        return cli_project.strip()
    for var in ("CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"):
        v = os.environ.get(var)
        if v and v.strip():
            return v.strip()
    if shutil_which("gcloud"):
        try:
            p = subprocess.run(["gcloud", "config", "get-value", "project"],
                               capture_output=True, text=True, timeout=30,
                               env=gcloud_env(""))
            v = (p.stdout or "").strip()
            if v and v != "(unset)":
                return v
        except Exception:
            pass
    sys.exit("LỖI: chưa xác định GCP project. Chạy với --project <PROJECT_ID>.")


def shutil_which(cmd: str):
    import shutil
    return shutil.which(cmd)


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def basename_of(v):
    if not isinstance(v, str) or not v:
        return v
    if v.startswith(("http://", "https://", "projects/", "global/", "regions/",
                     "zones/", "serviceAccounts/", "gs://")):
        return v.rstrip("/").rsplit("/", 1)[-1]
    return v


def extract_name(rec: dict) -> str:
    n = rec.get("name") if isinstance(rec, dict) else None
    if not (isinstance(n, str) and n):
        md = rec.get("metadata") if isinstance(rec, dict) else None
        n = md.get("name") if isinstance(md, dict) else None
    if not (isinstance(n, str) and n):
        return ""
    return basename_of(n)


def _path_location(name_raw) -> str:
    if isinstance(name_raw, str) and "/locations/" in name_raw:
        m = re.search(r"/locations/([^/]+)", name_raw)
        if m:
            return m.group(1)
    return ""


def extract_region(rec: dict, mode, ctx: dict):
    """
    Trích region của resource để lọc theo --regions.
    mode: None (global — luôn giữ) | region | zone | region_or_zone |
          location | config (Spanner)
    Trả về None = không xác định được → GIỮ resource (không âm thầm loại).
    """
    if mode is None:
        return None

    def zone_to_region(z: str) -> str:
        z = basename_of(z)
        return z.rsplit("-", 1)[0] if re.match(r".+-[a-z]$", z) else z

    if mode in ("region", "region_or_zone"):
        v = rec.get("region")
        if isinstance(v, str) and v:
            return basename_of(v)
    if mode in ("zone", "region_or_zone"):
        v = rec.get("zone")
        if isinstance(v, str) and v:
            return zone_to_region(v)
    if mode == "location":
        v = rec.get("location")
        if isinstance(v, str) and v:
            return basename_of(v)
        locs = rec.get("locations")
        if isinstance(locs, list):
            for item in locs:
                p = _path_location(item)
                if p:
                    return p
    if mode == "config":
        m = re.search(r"regional-([a-z0-9\-]+)", str(rec.get("config") or ""))
        if m:
            return m.group(1)

    # Fallback chung: path trong name (projects/.../locations/<loc>/...)
    name_raw = rec.get("name") if isinstance(rec, dict) else None
    if not (isinstance(name_raw, str) and name_raw):
        md = rec.get("metadata") if isinstance(rec, dict) else None
        name_raw = md.get("name") if isinstance(md, dict) else None
    p = _path_location(name_raw)
    if p:
        return p

    # Fallback: label/annotation kiểu cloud.googleapis.com/location (Cloud Run knative)
    md = rec.get("metadata") if isinstance(rec, dict) else None
    if isinstance(md, dict):
        for container in ("labels", "annotations"):
            d = md.get(container)
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, str) and v and (
                            k.endswith("/location") or k.endswith("/region")
                            or k in ("location", "region")):
                        return v

    # Fallback: biết region từ lúc list (per-region/per-location)
    return ctx.get("region") or ctx.get("location") or None


# ---------------------------------------------------------------------------
# Template lệnh
# ---------------------------------------------------------------------------

def render(template: str, mapping: dict) -> list[str]:
    fields = {fn for _, fn, _, _ in Formatter().parse(template) if fn}
    missing = sorted(f for f in fields if f not in mapping)
    if missing:
        raise KeyError(f"thiếu placeholder {missing}: {template}")
    rendered = template.format(**{k: str(v) for k, v in mapping.items()})
    return [t for t in shlex.split(rendered) if t != ""]


def build_mapping(rec: dict, ctx: dict) -> dict:
    name = extract_name(rec)
    region = ""
    v = rec.get("region")
    if isinstance(v, str) and v:
        region = basename_of(v)
    if not region:
        region = _path_location(rec.get("name")) or str(ctx.get("region") or "")
    zone = basename_of(rec.get("zone")) if isinstance(rec.get("zone"), str) else ""
    location = ""
    v = rec.get("location")
    if isinstance(v, str) and v:
        location = basename_of(v)
    if not location and isinstance(rec.get("locations"), list):
        for item in rec["locations"]:
            location = _path_location(item)
            if location:
                break
    if not location:
        location = region or zone or str(ctx.get("location") or ctx.get("region") or "")
    return {
        "name": name,
        "region": region,
        "zone": zone,
        "location": location,
        "region_flag": f"--region={region}" if region else "",
        "zone_flag": f"--zone={zone}" if zone else "",
        "location_flag": f"--location={location}" if location else "",
    }


# ---------------------------------------------------------------------------
# REGISTRY — 11 service theo yêu cầu
# ---------------------------------------------------------------------------
# group: name (khóa trong JSON), list, describe,
#        per_region/per_location (lặp theo --regions),
#        region_from (cách trích region để lọc: None = global, luôn giữ)

SERVICES = [
    dict(key="vpc", file="01_vpc.json", service="VPC", api="compute.googleapis.com",
         groups=[dict(name="networks", list="compute networks list",
                      describe="compute networks describe {name}",
                      region_from=None)]),
    dict(key="subnet", file="02_subnet.json", service="Subnet",
         api="compute.googleapis.com",
         groups=[dict(name="subnets", list="compute networks subnets list",
                      describe="compute networks subnets describe {name} --region={region}",
                      region_from="region")]),
    dict(key="firewall", file="03_firewall.json", service="Firewall",
         api="compute.googleapis.com",
         groups=[dict(name="firewall_rules", list="compute firewall-rules list",
                      describe="compute firewall-rules describe {name}",
                      region_from=None)]),
    dict(key="cloud_armor", file="04_cloud_armor.json", service="Cloud Armor",
         api="compute.googleapis.com",
         groups=[dict(name="security_policies", list="compute security-policies list",
                      describe="compute security-policies describe {name} {region_flag}",
                      region_from="region")]),
    dict(key="certificate_manager", file="05_certificate_manager.json",
         service="Cloud Certificate Manager", api="certificatemanager.googleapis.com",
         groups=[dict(name="certificates",
                      list="certificate-manager certificates list --location={location}",
                      describe="certificate-manager certificates describe {name} --location={location}",
                      per_location=True, region_from="location")]),
    dict(key="load_balancer", file="06_load_balancer.json", service="Load Balancer",
         api="compute.googleapis.com",
         groups=[
             dict(name="addresses", list="compute addresses list",
                  describe="compute addresses describe {name} {region_flag}",
                  region_from="region"),
             dict(name="forwarding_rules", list="compute forwarding-rules list",
                  describe="compute forwarding-rules describe {name} {region_flag}",
                  region_from="region"),
             dict(name="target_http_proxies", list="compute target-http-proxies list",
                  describe="compute target-http-proxies describe {name} {region_flag}",
                  region_from="region"),
             dict(name="target_https_proxies", list="compute target-https-proxies list",
                  describe="compute target-https-proxies describe {name} {region_flag}",
                  region_from="region"),
             dict(name="target_tcp_proxies", list="compute target-tcp-proxies list",
                  describe="compute target-tcp-proxies describe {name} {region_flag}",
                  region_from="region"),
             dict(name="target_ssl_proxies", list="compute target-ssl-proxies list",
                  describe="compute target-ssl-proxies describe {name} {region_flag}",
                  region_from="region"),
             dict(name="url_maps", list="compute url-maps list",
                  describe="compute url-maps describe {name} {region_flag}",
                  region_from="region"),
             dict(name="backend_services", list="compute backend-services list",
                  describe="compute backend-services describe {name} {region_flag}",
                  region_from="region"),
             dict(name="health_checks", list="compute health-checks list",
                  describe="compute health-checks describe {name} {region_flag}",
                  region_from="region"),
             dict(name="negs", list="compute network-endpoint-groups list",
                  describe="compute network-endpoint-groups describe {name} {region_flag} {zone_flag}",
                  region_from="region_or_zone"),
         ]),
    dict(key="cloud_run", file="07_cloud_run.json", service="Cloud Run",
         api="run.googleapis.com",
         groups=[
             dict(name="services", list="run services list --region={region}",
                  describe="run services describe {name} --region={region}",
                  per_region=True, region_from="location"),
             dict(name="jobs", list="run jobs list --region={region}",
                  describe="run jobs describe {name} --region={region}",
                  per_region=True, region_from="location"),
         ]),
    dict(key="cloud_storage", file="08_cloud_storage.json", service="Cloud Storage",
         api="storage.googleapis.com",
         groups=[dict(name="buckets", list="storage buckets list",
                      describe="storage buckets describe gs://{name}",
                      region_from="location")]),
    dict(key="vm", file="09_vm.json", service="VM (Compute Engine)",
         api="compute.googleapis.com",
         groups=[dict(name="instances", list="compute instances list",
                      describe="compute instances describe {name} --zone={zone}",
                      region_from="zone")]),
    dict(key="spanner", file="10_spanner.json", service="Cloud Spanner",
         api="spanner.googleapis.com",
         groups=[dict(name="instances", list="spanner instances list",
                      describe="spanner instances describe {name}",
                      region_from="config")]),
    dict(key="redis", file="11_redis.json", service="Memorystore (Redis)",
         api="redis.googleapis.com",
         groups=[dict(name="instances", list="redis instances list --region={region}",
                      describe="redis instances describe {name} --region={region}",
                      per_region=True, region_from="region")]),
    dict(key="dedicated_interconnect", file="12_dedicated_interconnect.json",
         service="Dedicated Interconnect", api="interconnect.googleapis.com",
         groups=[
             # Physical circuit → không lọc theo region (vị trí co-lo không phải Tokyo/Osaka)
             dict(name="connections", list="compute interconnects list",
                  describe="compute interconnects describe {name}",
                  region_from=None),
             dict(name="attachments", list="compute interconnects attachments list",
                  describe="compute interconnects attachments describe {name} {region_flag}",
                  region_from=None),
         ]),
    dict(key="ha_vpn", file="13_ha_vpn.json", service="Cloud HA VPN",
         api="compute.googleapis.com",
         groups=[
             dict(name="vpn_gateways", list="compute vpn-gateways list",
                  describe="compute vpn-gateways describe {name} --region={region}",
                  region_from="region"),
             dict(name="vpn_tunnels", list="compute vpn-tunnels list",
                  describe="compute vpn-tunnels describe {name} --region={region}",
                  region_from="region"),
             # External gateway (phía on-prem) là global → luôn giữ
             dict(name="external_vpn_gateways",
                  list="compute external-vpn-gateways list",
                  describe="compute external-vpn-gateways describe {name}",
                  region_from=None),
         ]),
    dict(key="cloud_router", file="14_cloud_router.json", service="Cloud Router",
         api="compute.googleapis.com",
         groups=[dict(name="routers", list="compute routers list",
                      describe="compute routers describe {name} --region={region}",
                      region_from="region")]),
]


# ---------------------------------------------------------------------------
# Thu thập dữ liệu
# ---------------------------------------------------------------------------

def append_error(errors: list, stage: str, group: str, name: str, cmd: str, msg: str):
    errors.append({"stage": stage, "group": group, "resource": name,
                   "cmd": cmd, "error": redact_text(msg or "")[:500]})


def dedupe_key(rec: dict, ctx: dict):
    """Khóa dedupe — phải phân biệt được resource cùng tên ở region khác nhau
    (vd: subnet 'default' ở 42 region). Ưu tiên selfLink/id/uid (unique)."""
    for k in ("selfLink", "id"):
        v = rec.get(k)
        if isinstance(v, str) and v:
            return v
    md = rec.get("metadata")
    if isinstance(md, dict) and md.get("uid"):
        return f"uid:{md['uid']}"
    return json.dumps([extract_name(rec), rec.get("region"), rec.get("zone"),
                       rec.get("location"), ctx], sort_keys=True, default=str)


def list_once(group: dict, base_ctx: dict, project: str, errors: list):
    """Chạy 1 lệnh list → [(record, ctx), ...]."""
    try:
        cmd = render(group["list"], dict(base_ctx))
    except (KeyError, ValueError) as e:
        append_error(errors, "list-render", group["name"], "", group["list"], str(e))
        return []
    data, err = run_gcloud(cmd, project)
    if err:
        append_error(errors, "list", group["name"], "", " ".join(cmd), err)
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        append_error(errors, "list", group["name"], "", " ".join(cmd),
                     f"JSON không hợp lệ: {str(data)[:100]}")
        return []
    return [(r, dict(base_ctx)) for r in data if isinstance(r, dict)]


def describe_one(group: dict, rec: dict, ctx: dict, project: str, errors: list):
    """Describe 1 resource → dict JSON; lỗi → None (fallback dùng record list)."""
    name = extract_name(rec)
    try:
        cmd = render(group["describe"], build_mapping(rec, ctx))
    except (KeyError, ValueError) as e:
        append_error(errors, "describe-render", group["name"], name,
                     group["describe"], str(e))
        return None
    data, err = run_gcloud(cmd, project)
    if err:
        append_error(errors, "describe", group["name"], name, " ".join(cmd), err)
        return None
    if isinstance(data, dict):
        return data
    append_error(errors, "describe", group["name"], name, " ".join(cmd),
                 f"JSON không hợp lệ: {str(data)[:100]}")
    return None


def collect_group(group: dict, regions: list[str], project: str, errors: list,
                  workers: int):
    """
    List (lặp theo per_region/per_location nếu có) → lọc region → describe song song.
    Trả về (list[dict] JSON resource, count trước khi lọc region).
    """
    # 1) List
    raw: list[tuple[dict, dict]] = []
    if group.get("per_location"):
        for loc in ["global", *regions]:
            raw.extend(list_once(group, {"location": loc}, project, errors))
    elif "{region}" in group["list"]:
        for r in regions:
            raw.extend(list_once(group, {"region": r}, project, errors))
    else:
        raw.extend(list_once(group, {}, project, errors))

    # Dedupe (list lặp theo region/location có thể trùng)
    seen = set()
    records: list[tuple[dict, dict]] = []
    for rec, ctx in raw:
        k = dedupe_key(rec, ctx)
        if k in seen:
            continue
        seen.add(k)
        records.append((rec, ctx))
    count_all = len(records)

    # 2) Lọc theo region (resource global hoặc không trích được region → giữ)
    regions_l = {r.lower() for r in regions}
    kept = []
    for rec, ctx in records:
        reg = extract_region(rec, group.get("region_from"), ctx)
        if reg and reg.lower() != "global" and reg.lower() not in regions_l:
            continue
        kept.append((rec, ctx))

    # 3) Describe song song
    results = [None] * len(kept)
    if kept:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = {ex.submit(describe_one, group, rec, ctx, project, errors): i
                    for i, (rec, ctx) in enumerate(kept)}
            for fut in as_completed(futs):
                i = futs[fut]
                data = fut.result()
                results[i] = data if isinstance(data, dict) else kept[i][0]
    return results, count_all


def derive_path_matchers(out: dict):
    """
    ALB: trích Path matcher từ URL map ra group riêng 'path_matchers'
    (mỗi path matcher 1 record kèm hosts tương ứng → dễ đưa vào Excel).
    Dữ liệu nguồn đã qua redact nên output cũng đã redact.
    """
    pms = []
    for um in out["groups"].get("url_maps", []):
        if not isinstance(um, dict):
            continue
        um_name = extract_name(um)
        host_rules = um.get("hostRules") or []
        for pm in um.get("pathMatchers") or []:
            if not isinstance(pm, dict):
                continue
            hosts = []
            for hr in host_rules:
                if isinstance(hr, dict) and hr.get("pathMatcher") == pm.get("name"):
                    hosts.extend(hr.get("hosts") or [])
            row = {"url_map": um_name, "hosts": hosts}
            row.update(pm)
            pms.append(row)
    # Luôn có key (kể cả rỗng) để schema ổn định cho tool xử lý Excel downstream
    out["groups"]["path_matchers"] = pms
    out["count"] += len(pms)
    out["count_all"] += len(pms)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="Xuất setting GCP ra 1 file JSON/service cho parameter sheet.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--project", "-p", help="GCP project ID")
    p.add_argument("--regions", default=DEFAULT_REGIONS,
                   help=f"Region lọc resource, phân cách dấu phẩy (mặc định: {DEFAULT_REGIONS})")
    p.add_argument("--only", help="Chỉ xuất service nào, phân cách dấu phẩy "
                                  "(vd: vpc,load_balancer)")
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p.add_argument("--workers", type=int, default=8, help="Số lệnh describe song song")
    p.add_argument("--no-redact", action="store_true",
                   help="Tắt redact secret (chỉ khi chắc chắn JSON không chứa secret)")
    args = p.parse_args()

    project = resolve_project(args.project)
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    if not regions:
        sys.exit("LỖI: --regions rỗng.")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = SERVICES
    if args.only:
        keys = {k.strip() for k in args.only.split(",") if k.strip()}
        valid = {s["key"] for s in SERVICES}
        bad = sorted(keys - valid)
        if bad:
            sys.exit(f"LỖI --only: không tồn tại {', '.join(bad)}\n"
                     f"Key hợp lệ: {', '.join(sorted(valid))}")
        selected = [s for s in SERVICES if s["key"] in keys]

    print(f"Project: {project} · Region: {', '.join(regions)} · "
          f"{len(selected)} service")
    now = datetime.now(timezone.utc)
    total_res = 0
    total_all = 0
    total_errors = 0

    for svc in selected:
        out = {
            "service": svc["service"],
            "api": svc["api"],
            "project": project,
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "regions": regions,
            "groups": {},
            "count": 0,
            "count_all": 0,
            "errors": [],
        }
        for group in svc["groups"]:
            datas, count_all = collect_group(group, regions, project, out["errors"],
                                             args.workers)
            if not args.no_redact:
                datas = [redact_obj(d) for d in datas]
            out["groups"][group["name"]] = datas
            out["count"] += len(datas)
            out["count_all"] += count_all
        if svc["key"] == "load_balancer":
            derive_path_matchers(out)
        if not args.no_redact:
            out["errors"] = [redact_obj(e) for e in out["errors"]]

        path = out_dir / svc["file"]
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
        note = "" if out["count"] == out["count_all"] else \
            f" (trước lọc region: {out['count_all']})"
        err_note = f" · ⚠ {len(out['errors'])} lỗi" if out["errors"] else ""
        print(f"  {svc['file']}: {out['count']} resource{note}{err_note}")
        if out["errors"]:
            e0 = out["errors"][0]
            print(f"      ↳ lỗi đầu tiên [{e0['stage']}] {e0['group']}/"
                  f"{e0['resource']}: {e0['error'][:200]}")
        total_res += out["count"]
        total_all += out["count_all"]
        total_errors += len(out["errors"])

    print(f"HOÀN TẤT — {len(selected)} file JSON trong {out_dir}/")
    print(f"  Tổng resource: {total_res} (trước lọc region: {total_all}) · "
          f"lỗi: {total_errors}")
    if total_errors:
        print("  Lỗi ghi trong trường 'errors' của từng file JSON "
              "(thường do API chưa bật / chưa có permission).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

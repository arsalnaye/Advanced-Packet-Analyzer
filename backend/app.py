from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BACKEND_DIR / "results"
BIN_DIR = BACKEND_DIR / "bin"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_PACKET_SAMPLES = 250
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
BIN_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="PacketScope API", version="0.1.0", description="Local API for the Advanced Packet Analyzer.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:4173", "http://localhost:4173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def _valid_existing_engine(path: Path) -> bool:
    """Avoid attempting to execute the repository's bundled binary on the wrong OS."""
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return False
    system = platform.system()
    if system == "Windows":
        return path.suffix.lower() == ".exe" and magic[:2] == b"MZ"
    if system == "Darwin":
        return magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
    return magic == b"\x7fELF"


def _engine_candidates() -> list[Path]:
    configured = os.getenv("DPI_ENGINE_PATH")
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser().resolve())
    if os.name == "nt":
        candidates.extend([ROOT / "dpi_engine.exe", BIN_DIR / "dpi_engine.exe"])
    else:
        candidates.extend([ROOT / "dpi_engine", BIN_DIR / "dpi_engine"])
    return candidates


def _compile_engine() -> Path:
    """Compile the repo's multi-threaded DPI CLI if no compatible binary is present."""
    sources = [
        "src/dpi_mt.cpp",
        "src/pcap_reader.cpp",
        "src/packet_parser.cpp",
        "src/sni_extractor.cpp",
        "src/types.cpp",
    ]
    if any(not (ROOT / source).is_file() for source in sources):
        raise HTTPException(status_code=500, detail="The C++ DPI engine source files are missing from the project folder.")

    if os.name == "nt":
        output = BIN_DIR / "dpi_engine.exe"
        gpp = shutil.which("g++")
        if gpp:
            command = [gpp, "-std=c++17", "-pthread", "-O2", "-I", str(ROOT / "include"), "-o", str(output)] + [str(ROOT / item) for item in sources]
        else:
            cl = shutil.which("cl.exe") or shutil.which("cl")
            if not cl:
                raise HTTPException(status_code=503, detail="No compatible DPI executable was found. Install g++ (MinGW/MSYS2) or run the API from a Visual Studio Developer Command Prompt where cl.exe is available.")
            command = [cl, "/EHsc", "/std:c++17", "/O2", f"/I{ROOT / 'include'}", f"/Fo{BIN_DIR}{os.sep}", f"/Fe:{output}"] + [str(ROOT / item) for item in sources]
    else:
        output = BIN_DIR / "dpi_engine"
        compiler = shutil.which("g++") or shutil.which("clang++")
        if not compiler:
            raise HTTPException(status_code=503, detail="No compatible DPI executable was found and no g++ or clang++ compiler is available.")
        command = [compiler, "-std=c++17", "-pthread", "-O2", "-I", str(ROOT / "include"), "-o", str(output)] + [str(ROOT / item) for item in sources]

    try:
        build = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Building the DPI engine timed out. Compile it manually using WINDOWS_SETUP.md or README.md.") from exc
    if build.returncode != 0 or not output.exists():
        detail = (build.stderr or build.stdout or "Compiler did not produce an executable.")[-3500:]
        raise HTTPException(status_code=500, detail=f"Could not build the DPI engine. {detail}")
    return output


def get_engine() -> Path:
    for candidate in _engine_candidates():
        if candidate.is_file() and _valid_existing_engine(candidate):
            return candidate
    return _compile_engine()


def _parse_engine_report(output: str) -> dict[str, Any]:
    def number(label: str) -> int:
        match = re.search(rf"{re.escape(label)}\s*:\s*(\d+)", output, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    total = number("Total Packets")
    total_bytes = number("Total Bytes")
    tcp = number("TCP Packets")
    udp = number("UDP Packets")
    forwarded = number("Forwarded")
    dropped = number("Dropped")
    app_breakdown: list[dict[str, Any]] = []
    if "APPLICATION BREAKDOWN" in output:
        section = output.split("APPLICATION BREAKDOWN", 1)[1]
        section = section.split("Detected Domains/SNIs", 1)[0]
        for line in section.splitlines():
            # Do not depend on Unicode box-drawing characters: Windows native
            # console output may use a different code page. App rows are ASCII.
            match = re.search(r"^\s*[^A-Za-z0-9]*([A-Za-z][A-Za-z0-9 /&+_.-]*?)\s+(\d+)\s+(\d+(?:\.\d+)?)%", line)
            if match:
                name = match.group(1).strip()
                if name:
                    app_breakdown.append({"name": name, "count": int(match.group(2)), "percentage": float(match.group(3))})
    detected_domains: list[dict[str, str]] = []
    for match in re.finditer(r"^\s*-\s+([^\s]+)\s+->\s+(.+?)\s*$", output, re.MULTILINE):
        detected_domains.append({"domain": match.group(1), "application": match.group(2)})
    return {
        "stats": {"total_packets": total, "total_bytes": total_bytes, "tcp_packets": tcp, "udp_packets": udp, "forwarded": forwarded, "dropped": dropped},
        "app_breakdown": app_breakdown,
        "detected_domains": detected_domains,
    }


def _decode_network_frame(frame: bytes, number: int, timestamp: str) -> tuple[dict[str, Any], str | None, int, int]:
    """Decode enough Ethernet/IP/TCP/UDP metadata for a compact, safe packet table."""
    src = "—"
    dst = "—"
    shown_protocol = "Other"
    transport = "Other"
    src_port: int | None = None
    dst_port: int | None = None
    flags: list[str] = []
    info = "Frame metadata unavailable"
    offset = 14
    ethertype = int.from_bytes(frame[12:14], "big") if len(frame) >= 14 else 0

    # Support one or more common VLAN tags.
    while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4

    ip_protocol = None
    if ethertype == 0x0800 and len(frame) >= offset + 20:
        version_ihl = frame[offset]
        ihl = (version_ihl & 0x0F) * 4
        if (version_ihl >> 4) == 4 and ihl >= 20 and len(frame) >= offset + ihl:
            src = ".".join(str(x) for x in frame[offset + 12:offset + 16])
            dst = ".".join(str(x) for x in frame[offset + 16:offset + 20])
            ip_protocol = frame[offset + 9]
            offset += ihl
    elif ethertype == 0x86DD and len(frame) >= offset + 40:
        if frame[offset] >> 4 == 6:
            src = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
            dst = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
            ip_protocol = frame[offset + 6]
            offset += 40
    elif ethertype == 0x0806:
        shown_protocol = transport = "ARP"
        info = "Address resolution packet"
    else:
        if ethertype in (0x0800, 0x86DD):
            info = "Truncated IP frame"
        elif ethertype:
            info = f"EtherType 0x{ethertype:04x}"

    if ip_protocol == 6 and len(frame) >= offset + 20:
        transport = "TCP"
        src_port = int.from_bytes(frame[offset:offset + 2], "big")
        dst_port = int.from_bytes(frame[offset + 2:offset + 4], "big")
        flag_byte = frame[offset + 13]
        for mask, label in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")):
            if flag_byte & mask:
                flags.append(label)
        if src_port == 53 or dst_port == 53:
            shown_protocol, info = "DNS", "DNS over TCP"
        elif src_port in (80, 8080) or dst_port in (80, 8080):
            shown_protocol, info = "HTTP", "HTTP traffic"
        elif src_port == 443 or dst_port == 443:
            shown_protocol, info = "TLS", "TLS / HTTPS traffic"
        else:
            shown_protocol, info = "TCP", "TCP segment"
    elif ip_protocol == 17 and len(frame) >= offset + 8:
        transport = "UDP"
        src_port = int.from_bytes(frame[offset:offset + 2], "big")
        dst_port = int.from_bytes(frame[offset + 2:offset + 4], "big")
        if src_port in (53, 5353) or dst_port in (53, 5353):
            shown_protocol, info = "DNS", "DNS query / response"
        elif src_port in (67, 68) or dst_port in (67, 68):
            shown_protocol, info = "UDP", "DHCP traffic"
        else:
            shown_protocol, info = "UDP", "UDP datagram"
    elif ip_protocol == 1 or ip_protocol == 58:
        transport = shown_protocol = "ICMP"
        info = "ICMP control message"
    elif ip_protocol is not None:
        transport = shown_protocol = f"IP-{ip_protocol}"
        info = f"IP protocol {ip_protocol}"

    if src_port is not None:
        src_display = f"{src}:{src_port}"
        dst_display = f"{dst}:{dst_port}"
    else:
        src_display, dst_display = src, dst
    packet = {
        "number": number,
        "timestamp": timestamp,
        "source": src_display,
        "destination": dst_display,
        "protocol": shown_protocol,
        "length": len(frame),
        "src_port": src_port,
        "dst_port": dst_port,
        "info": info,
        "tcp_flags": ", ".join(flags) if flags else None,
    }
    return packet, transport, len(frame), ethertype


def _read_pcap(path: Path) -> dict[str, Any]:
    """Read classic pcap records. Packet rows are sampled, counters cover all records."""
    packets: list[dict[str, Any]] = []
    protocol_counts: Counter[str] = Counter()
    total = total_bytes = tcp = udp = 0
    try:
        with path.open("rb") as handle:
            global_header = handle.read(24)
            if len(global_header) != 24:
                raise ValueError("The file is too short to be a classic PCAP capture.")
            magic = global_header[:4]
            formats = {
                b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
                b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
                b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
                b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
            }
            if magic not in formats:
                raise ValueError("Unsupported capture format. Please use classic .pcap; PCAPNG files are not supported yet.")
            endian, fraction_scale = formats[magic]
            link_type = int.from_bytes(global_header[20:24], "little" if endian == "<" else "big")
            if link_type != 1:
                raise ValueError(f"This first version expects Ethernet PCAP captures (link type 1); received link type {link_type}.")
            while True:
                record_header = handle.read(16)
                if not record_header:
                    break
                if len(record_header) != 16:
                    raise ValueError("Capture contains a truncated packet record header.")
                sec, fraction, incl_len, _orig_len = __import__("struct").unpack(endian + "IIII", record_header)
                if incl_len > MAX_UPLOAD_BYTES:
                    raise ValueError("A packet record declares an unreasonable frame length.")
                frame = handle.read(incl_len)
                if len(frame) != incl_len:
                    raise ValueError("Capture contains a truncated packet frame.")
                total += 1
                total_bytes += incl_len
                transport_name = "Other"
                timestamp = datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%H:%M:%S") + "." + f"{fraction * 1_000_000 // fraction_scale:06d}"
                packet, transport_name, frame_len, _ethertype = _decode_network_frame(frame, total, timestamp)
                protocol_counts[transport_name] += 1
                tcp += int(transport_name == "TCP")
                udp += int(transport_name == "UDP")
                if len(packets) < MAX_PACKET_SAMPLES:
                    packets.append(packet)
    except OSError as exc:
        raise ValueError(f"Could not read the uploaded capture: {exc}") from exc
    return {
        "packets": packets,
        "protocol_breakdown": [{"name": name, "count": count} for name, count in protocol_counts.most_common()],
        "pcap_total_packets": total,
        "pcap_total_bytes": total_bytes,
        "pcap_tcp_packets": tcp,
        "pcap_udp_packets": udp,
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    available_binary = any(candidate.is_file() and _valid_existing_engine(candidate) for candidate in _engine_candidates())
    compiler_available = bool(shutil.which("g++") or shutil.which("clang++") or (os.name == "nt" and (shutil.which("cl.exe") or shutil.which("cl"))))
    return {"status": "ok", "engine_binary_available": available_binary, "compiler_available": compiler_available, "max_upload_bytes": MAX_UPLOAD_BYTES}


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    lbs: int = Form(2),
    fps: int = Form(2),
    rules: str = Form("[]"),
) -> dict[str, Any]:
    filename = Path(file.filename or "capture.pcap").name
    if not filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=415, detail="Please upload a classic .pcap file. PCAPNG is not supported yet.")
    if not (1 <= lbs <= 8 and 1 <= fps <= 8):
        raise HTTPException(status_code=422, detail="Thread settings must be between 1 and 8.")
    try:
        parsed_rules = json.loads(rules)
        if not isinstance(parsed_rules, list):
            raise ValueError
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Rules must be a JSON array.") from exc

    payload = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if not payload:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="The maximum upload size is 100 MB.")

    analysis_id = uuid.uuid4().hex
    input_path = BACKEND_DIR / f"upload_{analysis_id}.pcap"
    output_path = RESULTS_DIR / f"{analysis_id}.pcap"
    try:
        input_path.write_bytes(payload)
        try:
            pcap_details = _read_pcap(input_path)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        engine = get_engine()
        command = [str(engine), str(input_path), str(output_path), "--lbs", str(lbs), "--fps", str(fps)]
        valid_types = {"IP address": "--block-ip", "Domain": "--block-domain", "Application": "--block-app"}
        for rule in parsed_rules:
            if not isinstance(rule, dict) or rule.get("enabled") is False:
                continue
            rule_type = rule.get("type")
            value = str(rule.get("value", "")).strip()
            if rule_type not in valid_types or not value:
                continue
            if rule_type == "IP address":
                try:
                    parsed_ip = ipaddress.ip_address(value)
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=f"Invalid IP address rule: {value}") from exc
                if parsed_ip.version != 4:
                    raise HTTPException(status_code=422, detail="The current DPI engine supports IPv4 address blocking only.")
            elif rule_type == "Domain" and not re.fullmatch(r"[A-Za-z0-9*_.:-]{1,253}", value):
                raise HTTPException(status_code=422, detail=f"Invalid domain rule: {value}")
            elif rule_type == "Application" and not re.fullmatch(r"[A-Za-z0-9 /&+_.-]{1,80}", value):
                raise HTTPException(status_code=422, detail="Application rule contains unsupported characters.")
            command.extend([valid_types[rule_type], value])

        # Redirect the native Windows executable's output to a file instead of
        # relying on Python's PIPE capture. This is reliable across PowerShell,
        # Uvicorn reload workers, and different Windows console encodings.
        engine_log_path = RESULTS_DIR / f"{analysis_id}.log"
        try:
            with engine_log_path.open("wb") as engine_log:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdout=engine_log,
                    stderr=subprocess.STDOUT,
                    timeout=180,
                    check=False,
                )
            console_output = engine_log_path.read_bytes().decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(status_code=504, detail="Analysis exceeded the 180-second limit. Try a smaller PCAP file.") from exc
        finally:
            engine_log_path.unlink(missing_ok=True)

        if completed.returncode != 0 or not output_path.exists():
            message = (console_output or "The DPI engine failed without an error message.")[-3000:]
            raise HTTPException(status_code=500, detail=f"DPI engine failed: {message}")

        report = _parse_engine_report(console_output)
        # If report formatting differs on a platform/compiler, preserve reliable
        # PCAP statistics and derive forwarded/dropped counts from the output file.
        if report["stats"]["total_packets"] == 0 and pcap_details["pcap_total_packets"] > 0:
            output_details = _read_pcap(output_path)
            report["stats"].update({
                "total_packets": pcap_details["pcap_total_packets"],
                "total_bytes": pcap_details["pcap_total_bytes"],
                "tcp_packets": pcap_details["pcap_tcp_packets"],
                "udp_packets": pcap_details["pcap_udp_packets"],
                "forwarded": output_details["pcap_total_packets"],
                "dropped": max(0, pcap_details["pcap_total_packets"] - output_details["pcap_total_packets"]),
            })
        output_file_name = f"{Path(filename).stem}_filtered.pcap"
        (RESULTS_DIR / f"{analysis_id}.json").write_text(
            json.dumps({"file_name": filename, "output_file_name": output_file_name}), encoding="utf-8"
        )
        # The C++ engine's report is the authoritative DPI result. Header parsing adds
        # packet rows, including ports and timestamps, but does not claim payload visibility.
        return {
            "analysis_id": analysis_id,
            "file_name": filename,
            "output_file_name": output_file_name,
            **report,
            "protocol_breakdown": pcap_details["protocol_breakdown"],
            "packets": pcap_details["packets"],
            "output_download_url": f"/api/results/{analysis_id}/output",
            "log": console_output[-12000:],
            "capture_info": {
                "pcap_total_packets": pcap_details["pcap_total_packets"],
                "pcap_total_bytes": pcap_details["pcap_total_bytes"],
                "pcap_tcp_packets": pcap_details["pcap_tcp_packets"],
                "pcap_udp_packets": pcap_details["pcap_udp_packets"],
            },
        }
    finally:
        input_path.unlink(missing_ok=True)


@app.get("/api/results/{analysis_id}/output")
def download_output(analysis_id: str) -> FileResponse:
    if not re.fullmatch(r"[0-9a-f]{32}", analysis_id):
        raise HTTPException(status_code=404, detail="Analysis output not found.")
    output_path = RESULTS_DIR / f"{analysis_id}.pcap"
    if not output_path.is_file():
        raise HTTPException(status_code=404, detail="Analysis output has expired or does not exist.")
    metadata_path = RESULTS_DIR / f"{analysis_id}.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        metadata = {}
    download_name = metadata.get("output_file_name", f"{analysis_id}_filtered.pcap")
    return FileResponse(output_path, media_type="application/vnd.tcpdump.pcap", filename=download_name)

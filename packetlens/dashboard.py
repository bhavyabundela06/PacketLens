"""PacketLens dashboard (Streamlit).

Launch from the project folder (so .streamlit/config.toml is used):

    .venv/bin/streamlit run packetlens/dashboard.py

How Streamlit works (important for this file): the WHOLE script runs again
from top to bottom every time the user changes a widget. Therefore:
- analysing a capture, re-running detection, and deleting history only
  happen inside button handlers or one-shot callbacks, never on a rerun;
- analysing always creates a NEW database file, so a repeated click can
  never add the same packets twice;
- everything else is a read-only query and simply runs each time.

Design: quiet and editorial (see docs/architecture.md). Few boxes, hairline
dividers, one indigo accent; red only for suspicious things, amber only for
bursts. Wording is for non-technical users: "messages" = packets,
"devices" = IP addresses, "services"/"doors" = ports.
"""

import html
import math
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Allow "streamlit run packetlens/dashboard.py" from the project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packetlens import network_map, queries  # noqa: E402
from packetlens.database import SchemaVersionError, connect  # noqa: E402
from packetlens.detection import DetectionConfig, run_detection, stored_config  # noqa: E402
from packetlens.history import delete_captures, list_captures  # noqa: E402
from packetlens.ingest import IngestError, ingest_capture  # noqa: E402
from packetlens.queries import PacketFilter, QueryRejected, run_readonly_query  # noqa: E402
from packetlens.report import build_report  # noqa: E402
from packetlens.xml_export import export_xml  # noqa: E402

# Folders can be overridden (used by the automated dashboard test).
OUTPUT_DIR = Path(os.environ.get("PACKETLENS_OUTPUT_DIR", PROJECT_ROOT / "data/output"))
SAMPLE_DIR = Path(os.environ.get("PACKETLENS_SAMPLE_DIR", PROJECT_ROOT / "data/samples"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FILTER_KEYS = ("f_device", "f_service", "f_types", "f_time", "f_size", "f_label")

# Plain name, technical name.
TRAFFIC_TYPES = {
    "TCP": ("Connections", "TCP"),
    "UDP": ("Quick messages", "UDP"),
    "ICMP": ("Ping", "ICMP"),
    "ICMPv6": ("Ping", "ICMPv6"),
    "ARP": ("Address lookup", "ARP"),
    "OTHER": ("Other", ""),
}

RULE_TEXT = {
    "port_scan": (
        "Port scan",
        "One device tried many doors of the same computer in a short time, "
        "the way a scanner looks for open services.",
        "Yes. Administrators, security tools and some monitoring software "
        "do this on purpose.",
    ),
    "host_sweep": (
        "Host sweep",
        "One device tried to reach many different computers in a short time, "
        "the way someone maps which computers exist on a network.",
        "Yes. Monitoring systems, inventory tools and some peer-to-peer apps "
        "contact many computers on purpose.",
    ),
}

st.set_page_config(page_title="PacketLens", page_icon=":material/radio_button_checked:",
                   layout="wide", initial_sidebar_state="expanded")

THEME = "dark" if getattr(st.context.theme, "type", None) == "dark" else "light"
C = {
    "light": dict(accent="#4F5BD5", received="#C3C8F2", teal="#2BB3A3", red="#E5484D",
                  band="#FBF1DE", band_text="#875900", grey="#A7AAB3", grey2="#D4D6DB",
                  grid="#E7E6E1", axis="#6C6F78", hair="#E7E6E1", text="#17181C", button_text="#FAFAF8", fill="rgba(79,91,213,0.08)",
                  ok_bg="rgba(43,179,163,0.08)", bad_bg="#FBEBEC", bad_text="#C4262D"),
    "dark": dict(accent="#8F97F3", received="#3B4285", teal="#2BB3A3", red="#EF5F63",
                 band="rgba(242,166,90,0.14)", band_text="#F2C37A", grey="#6B6E77",
                 grey2="#3A3D44", grid="#25272C", axis="#8E9199", hair="#25272C", text="#ECECEE", button_text="#111215",
                 fill="rgba(143,151,243,0.10)", ok_bg="rgba(43,179,163,0.10)",
                 bad_bg="rgba(229,72,77,0.12)", bad_text="#EF5F63"),
}[THEME]

st.markdown(f"""
<style>
.block-container {{padding-top: 3rem; max-width: 1240px;}}
[data-testid="stDecoration"] {{display: none;}}
header[data-testid="stHeader"] {{background: transparent;}}
button[kind="primary"], button[data-testid="stBaseButton-primary"],
button[data-testid="stBaseButton-primaryFormSubmit"] {{
    color: {C['button_text']} !important; border: none;}}
.st-key-dropzone {{border-style: dashed !important; border-width: 1.5px !important;}}
.st-key-recent [data-testid="stHorizontalBlock"] {{border-top: 1px solid {C['hair']};
    padding: .65rem 0 .35rem;}}
.st-key-recent span {{white-space: nowrap;}}
.st-key-recent [data-testid="stHorizontalBlock"]:last-child {{
    border-bottom: 1px solid {C['hair']};}}
h1 {{font-size: 1.75rem !important; font-weight: 600 !important; letter-spacing: -0.02em;}}
h3 {{font-weight: 600 !important; letter-spacing: -0.01em;}}
.pl-sub {{color: {C['axis']}; margin: -0.9rem 0 1.4rem; font-size: .95rem;}}
.pl-eyebrow {{font-size: .72rem; letter-spacing: .09em; text-transform: uppercase;
             color: {C['axis']}; font-weight: 500;}}
.pl-muted {{color: {C['axis']};}}
.pl-status {{border-radius: 9px; padding: .8rem 1.1rem; margin-bottom: .8rem; font-size: .95rem;}}
.pl-status.bad {{background: {C['bad_bg']};}}
.pl-status.bad b {{color: {C['bad_text']}; font-weight: 600;}}
.pl-status.ok {{background: {C['ok_bg']};}}
.pl-dot {{display:inline-block; width:7px; height:7px; border-radius:50%;
         margin-right:.7rem; vertical-align: middle;}}
.pl-lede {{font-size: 1.7rem; line-height: 1.38; font-weight: 400; color: {C['axis']};
          letter-spacing: -0.015em; margin: .6rem 0 1.6rem;}}
.pl-lede b {{font-weight: 600; color: {C['text']};}}
.pl-lede .flag {{color: {C['red']}; font-weight: 600;}}
.st-key-stats {{border-top: 1px solid {C['hair']}; border-bottom: 1px solid {C['hair']};
               padding: 1.1rem 0 .6rem; margin-bottom: 1.6rem;}}
.st-key-stats [data-testid="stColumn"] + [data-testid="stColumn"] {{
    border-left: 1px solid {C['hair']}; padding-left: 1.3rem;}}
[data-testid="stMetricLabel"] p {{font-size: .72rem !important; letter-spacing: .09em;
                                 text-transform: uppercase; color: {C['axis']};}}
[data-testid="stMetricValue"] {{font-weight: 500; font-variant-numeric: tabular-nums;
    font-size: clamp(1.35rem, 2.3vw, 2.2rem) !important;}}
[data-testid="stMetricValue"] div, [data-testid="stMetricLabel"] div {{
    overflow: visible !important; text-overflow: clip !important;}}
.st-key-stats [data-testid="stMetricLabel"] p {{letter-spacing: .05em;}}
.pl-rowhead {{display:flex; justify-content:space-between; align-items:baseline;
             margin: .4rem 0 .2rem;}}
.pl-rowhead b {{font-weight: 600; font-size: 1.02rem;}}
.pl-list, .pl-kv {{width:100%; border-collapse: collapse; border: none !important;}}
.pl-list tr, .pl-kv tr {{background: none !important;}}
.pl-list td, .pl-kv td {{border: none !important; background: none !important;}}
.pl-list {{font-size: .93rem; margin: 0;}}
.pl-list td {{padding: .55rem 0 !important; border-bottom: 1px solid {C['hair']} !important;
             white-space: nowrap;}}
.pl-list td.num {{text-align: right; font-variant-numeric: tabular-nums;
                  padding-left: 1.1rem !important;}}
.pl-kinds {{display:flex; flex-wrap: wrap; gap: 1.6rem 2rem; align-items:center; margin-top: 1rem;}}
.pl-kinds .pl-list {{flex: 1 1 15rem; width: auto;}}
.pl-ring-wrap {{position: relative; width: 9.5rem; height: 9.5rem; flex: none;}}
.pl-ring-text {{position: absolute; inset: 0; display: flex; flex-direction: column;
               align-items: center; justify-content: center; line-height: 1.2;}}
.pl-ring-text span {{font-size: 1.6rem; font-weight: 500;}}
.pl-ring {{width: 100%; height: 100%; border-radius: 50%;
          -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 9px), #000 calc(100% - 8px));
          mask: radial-gradient(farthest-side, transparent calc(100% - 9px), #000 calc(100% - 8px));}}
.pl-bars {{display:grid; grid-template-columns: auto minmax(3.5rem, 1fr) auto; column-gap: 1rem; row-gap: .9rem;
          align-items:center; font-size: .93rem; font-variant-numeric: tabular-nums;}}
.pl-bars .bar {{height: 6px; border-radius: 3px; margin: 2px 0;}}
.pl-bars .val {{text-align:right; color: {C['axis']}; font-size: .85rem; white-space: nowrap;}}
.pl-flag {{color: {C['red']};}}
.pl-services {{display:grid; grid-template-columns: repeat(5, 1fr); gap: 2rem; margin-top: .8rem;}}
.pl-services .track {{height: 3px; background: {C['grid']}; border-radius: 2px; margin-bottom: .9rem;}}
.pl-services .fill {{height: 3px; border-radius: 2px;}}
.pl-services .n {{font-size: 1.65rem; font-weight: 500; line-height: 1.1;}}
.pl-big {{font-size: 3rem; font-weight: 500; line-height: 1; letter-spacing: -0.03em;}}
.pl-kv {{width:100%; border-collapse: collapse; font-size: .93rem; margin: .4rem 0 1rem;}}
.pl-kv td {{padding: .55rem 0 !important; border-top: 1px solid {C['hair']} !important;}}
.pl-kv td:last-child {{text-align: right;}}
.pl-tile {{display:inline-flex; width:3rem; height:3rem; border-radius: 8px; align-items:center;
          justify-content:center; font-family: ui-monospace, Menlo, monospace; font-size:.75rem;
          font-weight: 600; background: {C['grid']}; margin-right: .9rem; float:left;}}
.pl-hero {{font-size: 3rem; font-weight: 600; line-height: 1.08; letter-spacing: -0.035em;
          margin: .6rem 0 1rem;}}
.pl-steps {{display:grid; grid-template-columns: repeat(3, 1fr); gap: 2.2rem; margin-top: 3rem;}}
.pl-steps div {{border-top: 1.5px solid currentColor; padding-top: 1rem;}}
.pl-steps code {{background: none; padding: 0; color: {C['axis']};}}
.pl-empty {{text-align:center; padding: 3rem 0 1rem;}}
[class*="st-key-finding"] [data-testid="stExpander"] details {{
    border: none; border-top: 1px solid {C['hair']}; border-radius: 0;}}
[class*="st-key-finding"] [data-testid="stExpander"] summary {{padding-left: 0;}}
[data-testid="stSidebar"] [data-testid="stExpander"] details {{
    border: none; border-bottom: 1px solid {C['hair']}; border-radius: 0;}}
[data-testid="stSidebar"] [data-testid="stExpander"] summary {{padding-left: 0;}}
.pl-brand {{display:flex; gap:.75rem; align-items:flex-start; margin-bottom: 1.8rem;}}
.pl-brand b {{font-size: 1.05rem; font-weight: 600;}}
.pl-footer {{color: {C['axis']}; font-size: .82rem; margin-top: 2.5rem;}}
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def esc(value):
    return html.escape(str(value))


def clock(ts):
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")


def hms(ts, millis=False):
    text = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")
    return text[:-3] if millis else text[:8]


def human_bytes(value):
    value = float(value or 0)
    if value < 1000:
        return f"{value:,.0f} bytes"
    for unit in ("KB", "MB", "GB"):
        value /= 1000
        if value < 1000 or unit == "GB":
            return f"{value:,.1f} {unit}"


def short_bytes(value):
    """Compact size for tight spaces: 882 B, 1.9 KB, 2.1 MB."""
    text = human_bytes(value)
    return text.replace(" bytes", " B")


def human_duration(seconds):
    seconds = float(seconds or 0)
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} min {rest:.0f} s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)} h {int(minutes)} min"


def plural(count, word, words=None):
    return f"{count:,} {word if count == 1 else (words or word + 's')}"


def kind_label(protocol):
    name, tech = TRAFFIC_TYPES.get(protocol, (protocol, ""))
    return f"{name} ({tech})" if tech else name


def service_name(protocol, port):
    return network_map.service_label(protocol, port, None)


def eyebrow(text):
    st.markdown(f"<div class='pl-eyebrow'>{esc(text)}</div>", unsafe_allow_html=True)


def reset_filters():
    for key in FILTER_KEYS:
        st.session_state.pop(key, None)


def widen_time():
    st.session_state.pop("f_time", None)


def flash(kind, message):
    """Show a message after the next rerun (e.g. after st.rerun())."""
    st.session_state["flash"] = (kind, message)


WIDE_COLUMNS = {"Device A", "Device B", "Device", "From", "To", "Service", "Summary"}


def grid(rows):
    """A sortable table: address/service columns get room, numbers stay narrow."""
    data = pd.DataFrame(rows)
    config = {column: st.column_config.Column(width="medium" if column in WIDE_COLUMNS
                                              else "small")
              for column in data.columns}
    st.dataframe(data, hide_index=True, width="stretch", column_config=config)


def chart_layout(fig, height):
    fig.update_layout(height=height, margin=dict(l=4, r=4, t=8, b=4),
                      plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                      showlegend=False, hoverlabel=dict(font_size=13),
                      font=dict(color=C["axis"], size=11.5))
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=C["grid"],
                     tickfont=dict(color=C["axis"]))
    fig.update_yaxes(gridcolor=C["grid"], zeroline=False, tickfont=dict(color=C["axis"]))
    return fig


def analyse(uploaded, example):
    """Import an uploaded file or an example into a new database, then rerun."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    try:
        if uploaded is not None:
            stem = "".join(c if c.isalnum() or c in "-_" else "_"
                           for c in Path(uploaded.name).stem) or "capture"
            target = OUTPUT_DIR / f"{stem}-{stamp}.db"
            with tempfile.TemporaryDirectory() as directory:
                capture = Path(directory) / "upload.pcap"
                capture.write_bytes(uploaded.getvalue())
                counts = ingest_capture(capture, target, source_name=uploaded.name)
        elif example:
            target = OUTPUT_DIR / f"{Path(example).stem}-{stamp}.db"
            counts = ingest_capture(SAMPLE_DIR / example, target)
        else:
            raise IngestError("Choose a file or an example first.")
    except IngestError as error:
        st.error(f"Could not analyse this file. {error}")
        return
    # The Recording dropdown may already be drawn in this run, so switch to
    # the new recording at the start of the next run instead.
    st.session_state["next_capture"] = target.name
    st.session_state["view"] = "dashboard"
    reset_filters()
    flash("success", f"Analysed {plural(counts['packets'], 'message')} · found "
          f"{plural(counts['alerts'], 'suspicious pattern')}.")
    st.rerun()


def queue_example(key):
    """Pills callback: remember ONE requested example (handled once below)."""
    st.session_state["pending_example"] = st.session_state.get(key)
    st.session_state[key] = None


def burst_periods(timeline, bucket):
    """Merge neighbouring buckets with >= 3x the mean message count."""
    if len(timeline) <= 2:
        return []
    mean = timeline["packets"].mean()
    high = list(timeline["packets"] >= 3 * mean)
    periods, start = [], None
    for index, is_high in enumerate(high + [False]):
        if is_high and start is None:
            start = index
        elif not is_high and start is not None:
            periods.append((timeline["time"][start],
                            timeline["time"][index - 1] + pd.Timedelta(seconds=bucket),
                            (index - start) * bucket))
            start = None
    return periods


def pick_bucket(span):
    """Bucket size giving at most ~120 points, whatever the recording length."""
    for size in (0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 3600):
        if span / size <= 120:
            return size
    return 3600


def timeline_figure(timeline, bucket, column, unit, alerts, height):
    """Area chart + amber burst bands + red lanes for findings underneath."""
    fig = go.Figure(go.Scatter(
        x=timeline["time"], y=timeline[column], mode="lines", line_shape="spline",
        line=dict(width=2, color=C["accent"]), fill="tozeroy", fillcolor=C["fill"],
        hovertemplate="%{x|%H:%M:%S}<br><b>%{y:,.0f} " + unit + "</b><extra></extra>"))
    top = max(float(timeline[column].max()), 1.0)

    for start, end, length in burst_periods(timeline, bucket):
        fig.add_vrect(x0=start, x1=end, fillcolor=C["band"], opacity=1, line_width=0, layer="below")
        fig.add_annotation(x=start, y=top * 1.12, text=f"Burst · {human_duration(length)}",
                           showarrow=False, xanchor="left", font=dict(color=C["band_text"], size=11.5))

    # Red lanes below zero: one per finding, stacked if they overlap in time.
    lanes_end = []
    first, last = timeline["time"].iloc[0], timeline["time"].iloc[-1] + pd.Timedelta(seconds=bucket)
    for alert in alerts:
        start = pd.to_datetime(alert["start_ts"], unit="s", utc=True)
        end = pd.to_datetime(alert["end_ts"], unit="s", utc=True)
        if end < first or start > last:
            continue
        lane = next((i for i, busy in enumerate(lanes_end) if busy < start), len(lanes_end))
        if lane == len(lanes_end):
            lanes_end.append(end)
        else:
            lanes_end[lane] = end
        y = -top * (0.14 + 0.2 * lane)
        fig.add_shape(type="line", x0=start, x1=end, y0=y, y1=y,
                      line=dict(color=C["red"], width=3))
        who = alert["dst_ip"] if alert["rule"] == "port_scan" else alert["src_ip"]
        label = "Scan" if alert["rule"] == "port_scan" else "Sweep"
        fig.add_annotation(x=start, y=y, text=f"{label} · {esc(who)}", showarrow=False,
                           xanchor="left", yanchor="top", yshift=-3,
                           font=dict(color=C["red"], size=11.5))

    bottom = -top * (0.14 + 0.2 * len(lanes_end)) if lanes_end else 0
    chart_layout(fig, height)
    fig.update_yaxes(range=[bottom, top * 1.22], tickvals=[v for v in _nice_ticks(top)],
                     showticklabels=height > 250)
    fig.update_xaxes(tickformat="%H:%M:%S")
    return fig, len(lanes_end)


def _nice_ticks(top):
    step = 10 ** math.floor(math.log10(top)) if top >= 1 else 1
    for factor in (1, 2, 5, 10):
        if top / (step * factor) <= 5:
            step *= factor
            break
    return [step * i for i in range(int(top // step) + 1)]


# ------------------------------------------------------------------ state
history = list_captures(OUTPUT_DIR)
names = [entry["file"] for entry in history]
entries = {entry["file"]: entry for entry in history}
labels = {}
for entry in history:
    if entry["status"] == "ok":
        try:
            when = datetime.fromisoformat(entry["imported_at"]).strftime("%d %b, %H:%M")
        except (TypeError, ValueError):
            when = ""
        labels[entry["file"]] = (entry["source_name"], when)
    else:
        labels[entry["file"]] = (entry["file"], "old format" if entry["status"] == "old"
                                 else "unreadable")

# Every visit starts on the cover page ("home"); opening a recording
# switches to the dashboard view.
st.session_state.setdefault("view", "home")
if not history:
    st.session_state["view"] = "home"
VIEW = st.session_state["view"]


def open_recording(name):
    """Button callback: show the dashboard for one saved recording."""
    st.session_state["next_capture"] = name
    st.session_state["view"] = "dashboard"
    reset_filters()


def go_home():
    st.session_state["view"] = "home"


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.markdown(f"""
<div class='pl-brand'>
  <svg width="26" height="26" viewBox="0 0 26 26" style="flex:none;margin-top:2px">
    <circle cx="13" cy="13" r="11" fill="none" stroke="{C['text']}" stroke-width="1.6"/>
    <circle cx="16.5" cy="9.5" r="2.6" fill="{C['text']}"/>
  </svg>
  <div><b>PacketLens</b><br><span class='pl-muted'>Explore a saved network recording.</span></div>
</div>""", unsafe_allow_html=True)

    if VIEW == "dashboard":
        st.button("All recordings", icon=":material/arrow_back:", on_click=go_home,
                  key="home_button", type="tertiary")
        eyebrow("Recording")
        if st.session_state.get("next_capture") in names:
            st.session_state["capture"] = st.session_state.pop("next_capture")
        if st.session_state.get("capture") not in names:
            st.session_state["capture"] = names[0]
        st.selectbox("Recording", names, key="capture", label_visibility="collapsed",
                     format_func=lambda n: " · ".join(x for x in labels[n] if x),
                     on_change=reset_filters)

        with st.expander("Analyse a new recording", icon=":material/add:"):
            uploaded = st.file_uploader("Drop a .pcap or .pcapng file",
                                        type=["pcap", "pcapng", "cap"], key="upload")
            examples = sorted(p.name for p in SAMPLE_DIR.glob("*.pcap"))
            example = st.selectbox("Or try an example", examples, index=None,
                                   placeholder="Choose an example", key="sample")
            if st.button("Analyse", type="primary", key="analyse", width="stretch"):
                analyse(uploaded, example)

    if history:
        with st.expander(f"History  :gray[{len(history)}]", icon=":material/history:"):
            for name in names:
                title, when = labels[name]
                st.checkbox(f"{title}  :gray[{when}]", key=f"hist::{name}")
            chosen = [n for n in names if st.session_state.get(f"hist::{n}")]
            sure = st.checkbox("I understand this permanently deletes them",
                               key="delete_sure")
            if st.button("Clear selected history", key="delete_button", width="stretch",
                         disabled=not (sure and chosen)):
                removed = delete_captures([OUTPUT_DIR / n for n in chosen], OUTPUT_DIR)
                for key in [f"hist::{n}" for n in names] + ["capture", "delete_sure", "xml"]:
                    st.session_state.pop(key, None)
                if st.session_state.get("capture") in chosen or len(chosen) == len(names):
                    st.session_state["view"] = "home"
                reset_filters()
                flash("success", f"Removed {plural(removed, 'recording')} from history.")
                st.rerun()

    with st.expander("How to read this", icon=":material/menu_book:"):
        st.markdown(
            "**Message** :gray[(packet)]  \n:gray[one small piece of data sent over the network]\n\n"
            "**Device** :gray[(IP address)]  \n:gray[a computer or phone, shown by its network address]\n\n"
            "**Service** :gray[(port)]  \n:gray[what a message was for: web pages, name lookups, ping]\n\n"
            "**Conversation**  \n:gray[all messages between two devices for one service]\n\n"
            "**Suspicious pattern**  \n:gray[behaviour that looks like scanning. A hint to check, not proof]")

    st.markdown("<div class='pl-footer'>🔒&nbsp; Offline · nothing leaves this laptop</div>",
                unsafe_allow_html=True)

if "flash" in st.session_state:
    kind, message = st.session_state.pop("flash")
    getattr(st, kind)(message)

# ------------------------------------------------------------------ cover page
if VIEW == "home":
    eyebrow("PacketLens" if history else "Welcome")
    st.markdown("<div class='pl-hero'>See what happened<br>on a network.</div>",
                unsafe_allow_html=True)
    st.markdown("<p style='font-size:1.08rem;max-width:44rem' class='pl-muted'>Open a saved "
                "traffic recording and PacketLens explains it in plain English: who talked "
                "to whom, when, and whether anything looked suspicious.</p>",
                unsafe_allow_html=True)
    with st.container(border=True, key="dropzone"):
        drop, go_button = st.columns([5, 1], vertical_alignment="center")
        uploaded = drop.file_uploader("Drop a recording here · .pcap, .pcapng or .cap",
                                      type=["pcap", "pcapng", "cap"], key="welcome_upload")
        if go_button.button("Analyse", type="primary", key="welcome_analyse", width="stretch"):
            analyse(uploaded, None)
    examples = sorted(p.name for p in SAMPLE_DIR.glob("*.pcap"))
    if examples:
        st.pills("Or try an example", examples, key="example_pick",
                 on_change=queue_example, args=("example_pick",))
    pending = st.session_state.pop("pending_example", None)
    if pending:
        analyse(None, pending)

    if history:
        st.markdown("<div class='pl-rowhead' style='margin-top:2.6rem'><b>Recent recordings"
                    f"</b><span class='pl-muted'>{plural(len(history), 'saved analysis', 'saved analyses')}"
                    "</span></div>", unsafe_allow_html=True)
        with st.container(key="recent"):
            for name in names[:8]:
                entry = entries[name]
                title, when = labels[name]
                row = st.columns([5, 2.4, 1.6], vertical_alignment="center")
                if entry["status"] == "ok":
                    detail = f"Analysed {when} · {plural(entry['packets'] or 0, 'message')}"
                    found = entry["findings"] or 0
                    status = (f"<span class='pl-flag'>{plural(found, 'finding')}</span>" if found
                              else "<span class='pl-muted'>Nothing suspicious</span>")
                else:
                    detail, status = when.capitalize(), "<span class='pl-muted'>—</span>"
                row[0].markdown(f"<b>{esc(title)}</b><br><span class='pl-muted' "
                                f"style='font-size:.88rem'>{esc(detail)}</span>",
                                unsafe_allow_html=True)
                row[1].markdown(status, unsafe_allow_html=True)
                row[2].button("Open", key=f"open::{name}", on_click=open_recording,
                              args=(name,), icon=":material/arrow_forward:",
                              type="tertiary", disabled=entry["status"] != "ok")
            if len(names) > 8:
                st.caption(f"{len(names) - 8} older recordings are under History in the sidebar.")

    st.markdown("""
<div class='pl-steps'>
 <div><code>01</code><p><b>Load a recording</b><br><span class='pl-muted'>A .pcap file saved by
 Wireshark or tcpdump, or one of the examples.</span></p></div>
 <div><code>02</code><p><b>Explore</b><br><span class='pl-muted'>Who talked to whom, when, and how
 much, in charts, a map and tables.</span></p></div>
 <div><code>03</code><p><b>Check the findings</b><br><span class='pl-muted'>Anything that looks
 like scanning, explained, with a report to download.</span></p></div>
</div>""", unsafe_allow_html=True)
    st.stop()

# ------------------------------------------------------------------ open the recording
db_name = st.session_state["capture"]
db_path = OUTPUT_DIR / db_name

try:
    connection = connect(db_path, read_only=True)
except SchemaVersionError:
    st.title(db_name)
    st.error("This recording was analysed with an older version of PacketLens, so it "
             "can't be shown. Analyse the original file again, then remove this entry "
             "under History.")
    st.stop()
except Exception as error:  # e.g. not an SQLite file
    st.title(db_name)
    st.error(f"Cannot open this file: {error}. You can remove it under History.")
    st.stop()

info = queries.capture_info(connection) or {}
whole = queries.summary(connection)
all_alerts = queries.alerts(connection)
flagged = {alert["src_ip"] for alert in all_alerts}

# ------------------------------------------------------------------ header
st.title(info.get("source_name", db_name))
if whole["packets"]:
    st.markdown(f"<div class='pl-sub'>Recorded {clock(whole['first_ts'])} · lasting "
                f"{human_duration(whole['duration'])} · {plural(whole['packets'], 'message')}"
                "</div>", unsafe_allow_html=True)
else:
    st.markdown("<div class='pl-sub'>This recording contains no messages.</div>",
                unsafe_allow_html=True)

if all_alerts:
    rules = sorted({RULE_TEXT.get(a["rule"], (a["rule"],))[0].lower() for a in all_alerts})
    st.markdown(
        f"<div class='pl-status bad'><span class='pl-dot' style='background:{C['red']}'></span>"
        f"<b>{plural(len(all_alerts), 'suspicious pattern')} found</b> ({', '.join(rules)}). "
        "Open the Suspicious activity tab to see who, when, and the evidence.</div>",
        unsafe_allow_html=True)
else:
    st.markdown(
        f"<div class='pl-status ok'><span class='pl-dot' style='background:{C['teal']}'></span>"
        "<b>No suspicious patterns found</b> with the current detection settings.</div>",
        unsafe_allow_html=True)

# ------------------------------------------------------------------ focus (filters)
device_rows = queries.hosts(connection, None, limit=500)
device_counts = {row["ip"]: row["pkts_sent"] + row["pkts_recv"] for row in device_rows}
service_rows = queries.top_destination_ports(connection, None, limit=40)
service_protocol = {}
for row in service_rows:
    service_protocol.setdefault(row["dst_port"], row["protocol"])
present = [row["protocol"] for row in queries.protocol_distribution(connection)]

device = st.session_state.get("f_device") or "Any device"
service = st.session_state.get("f_service") or "Any service"
types = st.session_state.get("f_types") or []
size = st.session_state.get("f_size") or (0, 65535)
label = st.session_state.get("f_label") or "Any"
start_ts = end_ts = None
if st.session_state.get("f_time") and whole["packets"]:
    chosen_start, chosen_end = st.session_state["f_time"]
    if chosen_start.timestamp() > whole["first_ts"] or chosen_end.timestamp() <= whole["last_ts"]:
        start_ts, end_ts = chosen_start.timestamp(), chosen_end.timestamp()

packet_filter = PacketFilter(
    ip=None if device == "Any device" else device,
    port=None if service == "Any service" else int(service),
    protocols=list(types), start_ts=start_ts, end_ts=end_ts,
    min_length=size[0] or None,
    max_length=None if size[1] >= 65535 else size[1],
    l7_proto=None if label == "Any" else label,
)

chips = []
if packet_filter.ip:
    chips.append(packet_filter.ip)
if packet_filter.port is not None:
    chips.append(service_name(service_protocol.get(packet_filter.port, "TCP"), packet_filter.port))
chips += [kind_label(t) for t in packet_filter.protocols]
if start_ts is not None:
    chips.append(f"{hms(start_ts)} → {hms(end_ts)}")
if packet_filter.min_length or packet_filter.max_length:
    chips.append(f"{size[0]}–{size[1]} bytes")
if packet_filter.l7_proto:
    chips.append(packet_filter.l7_proto)

if chips:
    summary_text = "  ".join(f":gray-background[{c.replace('[', '(').replace(']', ')')}]"
                             for c in chips)
else:
    summary_text = (f":gray[Everything · {plural(len(device_rows), 'device')} · all services · "
                    f"all kinds · full {human_duration(whole['duration'])}]")

with st.expander(f"**Focus**  {summary_text}", icon=":material/tune:"):
    c1, c2, c3 = st.columns(3)
    c1.selectbox("Device", ["Any device"] + list(device_counts), key="f_device",
                 format_func=lambda ip: ip if ip == "Any device"
                 else f"{ip} · {plural(device_counts[ip], 'message')}")
    c2.selectbox("Service", ["Any service"] + list(service_protocol), key="f_service",
                 format_func=lambda p: p if p == "Any service"
                 else f"{service_name(service_protocol[p], p)} · port {p}")
    c3.multiselect("Kind of traffic", present, key="f_types", format_func=kind_label,
                   placeholder="All kinds")
    slider_col, options_col = st.columns([3, 1], vertical_alignment="bottom")
    if whole["packets"] and whole["duration"] > 0:
        start = datetime.fromtimestamp(whole["first_ts"], tz=timezone.utc)
        end = datetime.fromtimestamp(whole["last_ts"], tz=timezone.utc) + timedelta(milliseconds=1)
        slider_col.slider("Time window (UTC)", start, end, (start, end),
                          step=max((end - start) / 400, timedelta(milliseconds=1)),
                          format="HH:mm:ss", key="f_time")
    with options_col.popover("More options", width="stretch"):
        st.slider("Message size (bytes)", 0, 65535, (0, 65535), key="f_size")
        st.selectbox("Application", ["Any"] + queries.l7_labels(connection), key="f_label")
    options_col.button("Clear focus", on_click=reset_filters, key="clear_focus",
                       width="stretch", type="tertiary")

stats = queries.summary(connection, packet_filter)
no_match = stats["packets"] == 0 and not packet_filter.is_empty()
shown_alerts = queries.alerts(connection, packet_filter)

tab_names = ["Overview", "Network map", "Activity",
             f"Suspicious activity :red[{len(all_alerts)}]" if all_alerts else "Suspicious activity",
             "Details", "Reports"]
tabs = st.tabs(tab_names)


def no_match_message():
    st.markdown(f"<div class='pl-empty'><h3>No messages match this focus</h3>"
                f"<p class='pl-muted'>Nothing matches {esc(' · '.join(chips))}. Try a wider "
                "time window or another kind of traffic.</p></div>", unsafe_allow_html=True)
    _, a, b, _ = st.columns([2, 1, 1, 2])
    a.button("Clear focus", on_click=reset_filters, key="nm_clear",
             type="primary", width="stretch")
    b.button("Widen to full recording", on_click=widen_time, width="stretch",
             key="nm_widen", disabled=start_ts is None)


# ------------------------------------------------------------------ overview
with tabs[0]:
    host_rows = queries.hosts(connection, packet_filter, limit=10_000)
    talks = queries.conversations(connection, packet_filter, limit=100_000)

    if stats["packets"]:
        senders = queries.top_senders(connection, packet_filter, limit=1)
        lede = (f"In <b>{human_duration(stats['duration'])}</b>, "
                f"<b>{plural(len(host_rows), 'device')}</b> exchanged "
                f"<b>{plural(stats['packets'], 'message')}</b>.")
        # Lead with what matters: a flagged device if there is one, otherwise
        # the busiest sender.
        sent = {row["ip"]: row["pkts_sent"] for row in host_rows}
        suspects = sorted({a["src_ip"] for a in shown_alerts},
                          key=lambda ip: (-sent.get(ip, 0), ip))
        if suspects:
            ip = suspects[0]
            mine = [a for a in shown_alerts if a["src_ip"] == ip]
            targets = {a["dst_ip"] for a in mine if a["rule"] == "port_scan"}
            action = (f"knocked on the doors of {plural(len(targets), 'other device')}"
                      if targets else "tried to reach many computers")
            lede += f" <span class='flag'>{esc(ip)}</span> {action}"
            others = len(suspects) - 1
            lede += (f", and {plural(others, 'more device')} did something similar."
                     if others else ".")
        elif senders:
            top = senders[0]
            share = top["packets"] / stats["packets"]
            lede += (" Most of it came from " if share >= 0.5 else " The busiest sender was ")
            lede += f"<b>{esc(top['ip'])}</b> ({share:.0%} of messages)."
        st.markdown(f"<div class='pl-lede'>{lede}</div>", unsafe_allow_html=True)

    with st.container(key="stats"):
        empty = "—"
        cols = st.columns(5)
        cols[0].metric("Messages", f"{stats['packets']:,}")
        cols[1].metric("Data", human_bytes(stats["captured_bytes"]))
        cols[2].metric("Duration", human_duration(stats["duration"]) if stats["packets"] else empty)
        cols[3].metric("Devices", f"{len(host_rows):,}")
        cols[4].metric("Conversations", f"{len(talks):,}")

    if no_match:
        no_match_message()
    elif stats["packets"]:
        # --- over time strip
        span = max(stats["duration"], 0.01)
        bucket = pick_bucket(span)
        timeline = pd.DataFrame(queries.traffic_timeline(connection, packet_filter, bucket))
        timeline["time"] = pd.to_datetime(timeline["bucket_start"], unit="s", utc=True)
        st.markdown("<div class='pl-rowhead'><b>Over time</b>"
                    "<span class='pl-muted'>Messages per second</span></div>",
                    unsafe_allow_html=True)
        fig, _ = timeline_figure(timeline, bucket, "packets_per_sec", "messages per second",
                                 shown_alerts, 210)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False},
                        key="overview_timeline")

        left, right = st.columns(2, gap="large")
        # --- kinds of traffic
        with left:
            st.markdown("<div class='pl-rowhead'><b>Kinds of traffic</b></div>",
                        unsafe_allow_html=True)
            kinds = queries.protocol_distribution(connection, packet_filter)
            # Red and amber are reserved for "suspicious" and "burst".
            palette = [C["accent"], C["teal"], C["grey"], C["grey2"], C["received"], C["axis"]]
            # The ring is plain HTML/CSS (a conic gradient), so it scales
            # cleanly at any width and needs no chart library.
            stops, position = [], 0.0
            for color, k in zip(palette, kinds):
                share = 100 * k["packets"] / stats["packets"]
                stops.append(f"{color} {position:.2f}% {position + share:.2f}%")
                position += share
            rows = []
            for color, k in zip(palette, kinds):
                name, tech = TRAFFIC_TYPES.get(k["protocol"], (k["protocol"], ""))
                tech = f" <span class='pl-muted'>({tech})</span>" if tech else ""
                rows.append(
                    f"<tr><td><span class='pl-dot' style='background:{color};margin-right:.6rem'>"
                    f"</span>{esc(name)}{tech}</td>"
                    f"<td class='num pl-muted'>{k['packets'] / stats['packets']:.0%}</td>"
                    f"<td class='num'>{k['packets']:,}</td></tr>")
            st.markdown(
                f"<div class='pl-kinds'><div class='pl-ring-wrap'><div class='pl-ring' "
                f"style='background:conic-gradient({', '.join(stops)})'></div>"
                f"<div class='pl-ring-text'><span>{stats['packets']:,}</span>"
                f"<small class='pl-muted'>messages</small></div></div>"
                f"<table class='pl-list'>{''.join(rows)}</table></div>",
                unsafe_allow_html=True)

        # --- most active devices
        with right:
            st.markdown(
                "<div class='pl-rowhead'><b>Most active devices</b></div>"
                "<div class='pl-muted' style='font-size:.85rem'><span class='pl-dot' "
                f"style='background:{C['accent']};margin-right:.35rem'></span>Sent &nbsp;&nbsp;"
                f"<span class='pl-dot' style='background:{C['received']};margin-right:.35rem'>"
                "</span>Received</div>", unsafe_allow_html=True)
            top_hosts = host_rows[:5]
            biggest = max((max(h["bytes_sent"], h["bytes_recv"]) for h in top_hosts), default=1) or 1
            cells = []
            for h in top_hosts:
                name_class = "pl-flag" if h["ip"] in flagged else ""
                cells.append(
                    f"<div class='{name_class}'>{esc(h['ip'])}</div><div>"
                    f"<div class='bar' style='width:{100 * h['bytes_sent'] / biggest:.1f}%;"
                    f"background:{C['accent']}'></div>"
                    f"<div class='bar' style='width:{100 * h['bytes_recv'] / biggest:.1f}%;"
                    f"background:{C['received']}'></div></div>"
                    f"<div class='val'>{short_bytes(h['bytes_sent'])}<br>"
                    f"{short_bytes(h['bytes_recv'])}</div>")
            st.markdown(f"<div class='pl-bars' style='margin-top:1rem'>{''.join(cells)}</div>",
                        unsafe_allow_html=True)

        # --- what the traffic was for
        links = queries.network_links(connection, packet_filter)
        counts = {}
        for link in links:
            name = network_map.service_label(link["protocol"], link["service_port"], link["icmp_type"])
            counts[name] = counts.get(name, 0) + link["packets"]
        ranked = sorted(counts.items(), key=lambda item: -item[1])
        shown, rest = ranked[:4], ranked[4:]
        total = sum(counts.values()) or 1
        blocks = []
        for name, value in shown:
            plain, tech = network_map.split_label(name)
            blocks.append(
                f"<div><div class='track'><div class='fill' style='width:{100 * value / total:.0f}%;"
                f"background:{C['teal']}'></div></div><div class='n'>{value:,}</div>"
                f"<div>{esc(plain)}</div><div class='pl-muted'>{esc(tech) or '&nbsp;'}</div></div>")
        if rest:
            value = sum(v for _, v in rest)
            blocks.append(
                f"<div><div class='track'><div class='fill' style='width:{100 * value / total:.0f}%;"
                f"background:{C['grey']}'></div></div><div class='n'>{value:,}</div>"
                f"<div>Other services</div><div class='pl-muted'>"
                f"{plural(len(rest), 'kind')}</div></div>")
        if blocks:
            st.markdown("<div class='pl-rowhead' style='margin-top:2.2rem'>"
                        "<b>What the traffic was for</b></div>"
                        f"<div class='pl-services'>{''.join(blocks)}</div>",
                        unsafe_allow_html=True)

# ------------------------------------------------------------------ network map
with tabs[1]:
    if no_match:
        st.caption("No messages match this focus.")
    else:
        text_col, control_col = st.columns([3, 1], vertical_alignment="center")
        text_col.markdown("Read it left to right: each line is traffic going *from* a device, "
                          "*for* a service, *to* a device. Thicker means more messages.")
        detail = control_col.segmented_control(
            "Detail", ["Simple", "Normal", "Detailed"], default="Normal",
            key="map_detail", label_visibility="collapsed") or "Normal"
        links = queries.network_links(connection, packet_filter)
        if not links:
            st.caption("There is no device-to-device traffic to draw.")
        else:
            max_nodes = {"Simple": 4, "Normal": 7, "Detailed": 14}[detail]
            layers, edges = network_map.build_layers(links, max_nodes, flagged)
            st.plotly_chart(network_map.figure(layers, edges, flagged, THEME), width="stretch",
                            config={"displayModeBar": False}, key="map")
            legend = "".join(
                f"<span style='margin-right:1.4rem'><span class='pl-dot' style='background:{color};"
                f"margin-right:.4rem'></span>{text}</span>"
                for color, text in ((C["accent"], "Device"), (C["teal"], "Service"),
                                    (C["red"], "Flagged device and its traffic"),
                                    (C["grey"], "Smaller ones, grouped")))
            st.markdown(f"<div class='pl-muted' style='border-top:1px solid {C['hair']};"
                        f"padding-top:.9rem;font-size:.88rem'>{legend} Services are guessed "
                        "from door numbers (ports). Address lookups (ARP) are not drawn.</div>",
                        unsafe_allow_html=True)

# ------------------------------------------------------------------ activity
with tabs[2]:
    if not stats["packets"]:
        st.caption("No messages match this focus." if no_match else "No messages to show.")
    else:
        head, control = st.columns([3, 1], vertical_alignment="center")
        measure = control.segmented_control("Show", ["Messages", "Data"], default="Messages",
                                            key="activity_measure",
                                            label_visibility="collapsed") or "Messages"
        span = max(stats["duration"], 0.01)
        bucket = pick_bucket(span)
        head.markdown(f"**{measure} per second**  \n:gray[Each point covers "
                      f"{human_duration(bucket)}]")
        timeline = pd.DataFrame(queries.traffic_timeline(connection, packet_filter, bucket))
        timeline["time"] = pd.to_datetime(timeline["bucket_start"], unit="s", utc=True)
        column = "packets_per_sec" if measure == "Messages" else "bytes_per_sec"
        unit = "messages per second" if measure == "Messages" else "bytes per second"
        fig, lanes = timeline_figure(timeline, bucket, column, unit, shown_alerts, 440)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False},
                        key="activity_chart")

        periods = burst_periods(timeline, bucket)
        overlapping = [a for a in shown_alerts
                       if a["end_ts"] >= stats["first_ts"] and a["start_ts"] <= stats["last_ts"]]
        st.markdown(f"<div style='border-top:1px solid {C['hair']};margin:.6rem 0 1rem'></div>",
                    unsafe_allow_html=True)
        left, right = st.columns(2, gap="large")
        if periods:
            lengths = ", ".join(human_duration(p[2]) for p in periods)
            left.markdown(f"<span class='pl-dot' style='background:#E4A23A'></span>"
                          f"<b>{plural(len(periods), 'burst')}, lasting {lengths}</b><br>"
                          "<span class='pl-muted'>A moment with at least 3× the usual traffic. "
                          "Often just a download; not a problem by itself.</span>",
                          unsafe_allow_html=True)
        else:
            left.markdown("<span class='pl-dot' style='background:#A7AAB3'></span><b>No bursts"
                          "</b><br><span class='pl-muted'>Traffic never reached 3× its usual "
                          "level.</span>", unsafe_allow_html=True)
        if overlapping:
            right.markdown(f"<span class='pl-dot' style='background:{C['red']}'></span>"
                           f"<b>{plural(len(overlapping), 'finding')} in this window</b><br>"
                           "<span class='pl-muted'>Shown as red lines under the chart. Details "
                           "are in Suspicious activity.</span>", unsafe_allow_html=True)
        else:
            right.markdown("<span class='pl-dot' style='background:#2BB3A3'></span>"
                           "<b>Nothing suspicious in this window</b>", unsafe_allow_html=True)
        st.caption("This shows how much traffic there was, not how fast or healthy the "
                   "network was.")

# ------------------------------------------------------------------ suspicious
with tabs[3]:
    config = stored_config(connection) or DetectionConfig()
    st.markdown("PacketLens looks for two patterns that scanning tools produce. A finding is "
                "**a hint worth checking, not proof** of an attack.")
    if not packet_filter.is_empty():
        st.caption(f"Showing findings related to your focus ({len(shown_alerts)} of "
                   f"{len(all_alerts)}). Findings are always worked out on the whole recording.")
    if not shown_alerts:
        st.markdown(f"<div class='pl-empty'><h3>Nothing suspicious here</h3><p class='pl-muted'>"
                    "No device crossed the detection limits below.</p></div>",
                    unsafe_allow_html=True)

    for number, alert in enumerate(shown_alerts, 1):
        title, meaning, harmless = RULE_TEXT.get(alert["rule"], (alert["rule"], "", ""))
        is_scan = alert["rule"] == "port_scan"
        with st.container(border=True, key=f"finding_{alert['alert_id']}"):
            badge = "red" if alert["severity"] == "high" else "orange"
            st.markdown(f"<span class='pl-eyebrow'>Finding {number} of {len(shown_alerts)}"
                        f"</span> &nbsp; :{badge}-badge[{alert['severity'].capitalize()}]",
                        unsafe_allow_html=True)
            st.markdown(f"### {title} from :red[{alert['src_ip']}]")
            left, right = st.columns([5, 7], gap="large")
            noun = "different doors (ports)" if is_scan else "different computers"
            target = f"on **{alert['dst_ip']}**" if is_scan else ""
            span = alert["end_ts"] - alert["start_ts"]
            left.markdown(f"<span class='pl-big'>{alert['metric_value']}</span> &nbsp;{noun}",
                          unsafe_allow_html=True)
            left.markdown(f"reached {target} within {alert['window_seconds']:g} seconds. The "
                          f"limit is {alert['threshold']}. It lasted {human_duration(span)}, "
                          f"starting {hms(alert['start_ts'])} UTC.")
            left.markdown(f"**What it means**  \n{meaning}")
            left.markdown(f"**Could it be harmless?**  \n{harmless}")

            evidence = queries.evidence_with_results(connection, alert["alert_id"])
            if evidence:
                xs = [row["ts"] - alert["start_ts"] for row in evidence]
                if is_scan:
                    ys = [row["dst_port"] for row in evidence]
                else:
                    ys = [row["dst_ip"] for row in evidence]
                dots = go.Figure(go.Scatter(
                    x=xs, y=ys, mode="markers",
                    marker=dict(size=8, color=C["red"], opacity=0.85),
                    hovertemplate="+%{x:.2f} s<br>%{y}<extra></extra>"))
                chart_layout(dots, 300)
                dots.update_xaxes(ticksuffix=" s", tickprefix="+", showgrid=False)
                if is_scan:
                    low, high = min(ys), max(ys)
                    if high / max(low, 1) > 50:
                        dots.update_yaxes(type="log")
                else:
                    dots.update_yaxes(type="category", showticklabels=len(set(ys)) <= 25)
                with right:
                    st.caption("Each dot is one attempt · " +
                               ("door number by time" if is_scan else "computer by time"))
                    st.plotly_chart(dots, width="stretch", config={"displayModeBar": False},
                                    key=f"dots_{alert['alert_id']}")

            with st.expander(f"Evidence · {plural(alert['evidence_packets'], 'message')}"):
                grid([{
                    "Time (UTC)": hms(row["ts"], millis=True), "From": row["src_ip"],
                    "From door": row["src_port"], "To": row["dst_ip"],
                    "To door": row["dst_port"], "Result": row["result"]} for row in evidence])
                st.caption("Result comes from the reply, if the recording holds one: door "
                           "open = accepted, closed = refused, no answer = nothing came back.")

    with st.form("detection", border=True):
        st.markdown("**Detection settings** &nbsp; :gray[Lower numbers find more, and more "
                    "false alarms.]")
        a, b, c, d, e = st.columns(5, vertical_alignment="bottom")
        ports = a.number_input("Port scan: doors", 2, 65535, config.port_scan_ports)
        pwin = b.number_input("…within seconds", 0.1, 86400.0, float(config.port_scan_window))
        hosts_n = c.number_input("Host sweep: computers", 2, 1_000_000, config.host_sweep_hosts)
        hwin = d.number_input("…within seconds ", 0.1, 86400.0, float(config.host_sweep_window))
        if e.form_submit_button("Save and re-check", type="primary", width="stretch"):
            connection.close()
            count = run_detection(db_path, DetectionConfig(int(ports), float(pwin),
                                                           int(hosts_n), float(hwin)))
            flash("success", f"Re-checked with new settings: "
                  f"{plural(count, 'suspicious pattern')}.")
            st.rerun()

# ------------------------------------------------------------------ details
with tabs[4]:
    switch, note = st.columns([3, 2], vertical_alignment="center")
    view = switch.segmented_control(
        "View", ["Conversations", "Devices", "All messages", "Ask a question"],
        default="Conversations", key="details_view",
        label_visibility="collapsed") or "Conversations"

    if view == "Conversations":
        rows = queries.conversations(connection, packet_filter, limit=500)
        note.markdown(f"<div class='pl-muted' style='text-align:right'>"
                      f"{plural(len(rows), 'conversation')} · largest first</div>", unsafe_allow_html=True)
        grid([{
            "Device A": r["a_ip"], "Device B": r["b_ip"],
            "Service": service_name(r["protocol"], min(r["a_port"], r["b_port"])),
            "Messages": r["packet_count"], "Data": human_bytes(r["byte_count"]),
            "A → B / B → A": f"{r['packets_a_to_b']} / {r['packets_b_to_a']}",
            "Duration": human_duration(r["duration"]),
            "Started (UTC)": hms(r["start_ts"], millis=True)} for r in rows])

    elif view == "Devices":
        rows = queries.hosts(connection, packet_filter, limit=1000)
        note.markdown(f"<div class='pl-muted' style='text-align:right'>"
                      f"{plural(len(rows), 'device')} · busiest first</div>",
                      unsafe_allow_html=True)
        grid([{
            "Device": r["ip"], "Sent": r["pkts_sent"], "Received": r["pkts_recv"],
            "Data sent": human_bytes(r["bytes_sent"]),
            "Data received": human_bytes(r["bytes_recv"]),
            "First seen (UTC)": hms(r["first_seen"], millis=True),
            "Last seen (UTC)": hms(r["last_seen"], millis=True)} for r in rows])

    elif view == "All messages":
        page_size = 200
        pages = max(1, math.ceil(stats["packets"] / page_size))
        note.markdown(f"<div class='pl-muted' style='text-align:right'>"
                      f"{plural(stats['packets'], 'message')} · {page_size} per page</div>",
                      unsafe_allow_html=True)
        page = st.number_input(f"Page (of {pages})", 1, pages, 1, key="page")
        rows = queries.packets(connection, packet_filter, page_size, (page - 1) * page_size)
        grid([{
            "#": r["id"], "Time (UTC)": hms(r["ts"], millis=True), "From": r["src_ip"],
            "From door": r["src_port"], "To": r["dst_ip"], "To door": r["dst_port"],
            "Kind": kind_label(r["protocol"]), "Size (bytes)": r["length"],
            "Application": r["l7_proto"], "Summary": r["info"]} for r in rows])

    else:
        note.markdown("<div class='pl-muted' style='text-align:right'>🔒 Read-only · 500 rows · "
                      "2 s · focus not applied</div>", unsafe_allow_html=True)
        question = st.pills("Start from a ready-made question",
                            list(queries.CANNED_QUERIES) + ["Write my own"],
                            default=list(queries.CANNED_QUERIES)[0], key="canned")
        initial = queries.CANNED_QUERIES.get(question, "").strip()
        initial = "\n".join(line.strip() for line in initial.splitlines())
        sql_col, result_col = st.columns(2, gap="large")
        sql = sql_col.text_area("SQL", value=initial, height=220, key=f"sql-{question}")
        run = sql_col.button("Run", type="primary", key="run_sql", icon=":material/play_arrow:")
        result_col.markdown("**Result**")
        if run and sql.strip():
            started = time.perf_counter()
            try:
                columns, rows, truncated = run_readonly_query(db_path, sql)
            except QueryRejected as error:
                result_col.error(f"That question was refused or failed: {error}")
            else:
                result_col.caption(f"{plural(len(rows), 'row')} · "
                                   f"{time.perf_counter() - started:.2f} s"
                                   + (" · first 500 shown" if truncated else ""))
                result_col.dataframe(pd.DataFrame(rows, columns=columns), hide_index=True,
                                     width="stretch")
        else:
            result_col.caption("Press Run to see the answer.")

# ------------------------------------------------------------------ reports
with tabs[5]:
    report = build_report(db_path, packet_filter)
    covers = "Whole recording (no focus)" if packet_filter.is_empty() else "Current focus: " + " · ".join(chips)
    left, right = st.columns(2, gap="medium")
    with left.container(border=True):
        st.markdown("<span class='pl-tile'>HTML</span><b style='font-size:1.15rem'>Findings "
                    "report</b><br><span class='pl-muted'>A readable page for people. Opens in "
                    "any browser, offline.</span>", unsafe_allow_html=True)
        st.markdown(
            f"<table class='pl-kv'><tr><td>Covers</td><td>{esc(covers)}</td></tr>"
            "<tr><td>Sections</td><td>Summary, devices, conversations, findings, limits</td></tr>"
            f"<tr><td>Findings</td><td>{len(shown_alerts)}</td></tr>"
            f"<tr><td>Size</td><td>{human_bytes(len(report.encode()))}</td></tr></table>",
            unsafe_allow_html=True)
        st.download_button("Download report", report, file_name=f"{Path(db_name).stem}-report.html",
                           mime="text/html", type="primary", key="dl_report",
                           icon=":material/download:")
    with right.container(border=True):
        st.markdown("<span class='pl-tile'>XML</span><b style='font-size:1.15rem'>Full data "
                    "export</b><br><span class='pl-muted'>Every message, conversation, device and "
                    "finding, for other tools.</span>", unsafe_allow_html=True)
        prepared = st.session_state.get("xml", (None,))[0] == db_name
        size = human_bytes(len(st.session_state["xml"][1])) if prepared else "shown once prepared"
        st.markdown(
            "<table class='pl-kv'><tr><td>Covers</td><td>Whole recording (focus ignored)</td></tr>"
            f"<tr><td>Contains</td><td>{plural(whole['packets'], 'message')} · "
            f"{plural(len(queries.conversations(connection, None, limit=1_000_000)), 'conversation')}"
            f" · {plural(len(device_rows), 'device')}</td></tr>"
            f"<tr><td>Findings</td><td>{len(all_alerts)}</td></tr>"
            f"<tr><td>Size</td><td>{size}</td></tr></table>", unsafe_allow_html=True)
        if prepared:
            st.download_button("Download XML", st.session_state["xml"][1],
                               file_name=f"{Path(db_name).stem}.xml", mime="application/xml",
                               type="primary", key="dl_xml", icon=":material/download:")
        else:
            prep, hint = st.columns([1, 2], vertical_alignment="center")
            if prep.button("Prepare file", key="prepare_xml"):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "export.xml"
                    export_xml(db_path, target)
                    st.session_state["xml"] = (db_name, target.read_bytes())
                st.rerun()
            hint.caption("A download button appears when it is ready.")

connection.close()

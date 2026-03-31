#!/usr/bin/env python3
"""Analyze structured worker tool logs emitted by multi_agent_wf.

The worker log format is a repeated sequence of:

    [timestamp] run_id=<id> stage=<stage>
    { ... JSON event payload ... }

This script reconstructs call/return pairs, summarizes timing, highlights
negative or repeated calls, and reports long silent gaps between events.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


HEADER_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+run_id=(?P<run_id>\S+)\s+stage=(?P<stage>\S+)\s*$",
    re.MULTILINE,
)

NEGATIVE_PREFIXES = (
    "no ",
    "error",
    "function not found",
    "path not found",
    "request failed",
    "tool returned an error",
)


@dataclass
class LogEvent:
    timestamp: datetime
    run_id: str
    stage: str
    payload: dict[str, Any]


@dataclass
class CallPair:
    tool_call_id: str
    tool_name: str
    source: str
    args: dict[str, Any]
    start: datetime
    end: datetime
    duration_sec: float
    return_kind: str
    content: str
    negative: bool


@dataclass
class SpanPair:
    kind: str
    source: str
    work_item_id: str
    start: datetime
    end: datetime
    duration_sec: float
    payload: dict[str, Any]


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw)


def _json_signature(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def parse_worker_log(path: Path) -> list[LogEvent]:
    text = path.read_text(encoding="utf-8")
    matches = list(HEADER_RE.finditer(text))
    events: list[LogEvent] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        if not body:
            continue
        payload = json.loads(body)
        events.append(
            LogEvent(
                timestamp=_parse_timestamp(match.group("timestamp")),
                run_id=match.group("run_id"),
                stage=match.group("stage"),
                payload=payload,
            )
        )
    return events


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _is_negative_content(text: str) -> bool:
    lowered = text.strip().lower()
    if not lowered:
        return False
    return lowered.startswith(NEGATIVE_PREFIXES)


def pair_tool_events(events: Iterable[LogEvent]) -> tuple[list[CallPair], list[dict[str, Any]]]:
    pending: dict[str, LogEvent] = {}
    pairs: list[CallPair] = []
    unmatched: list[dict[str, Any]] = []

    for event in events:
        payload = event.payload
        kind = str(payload.get("kind") or "")
        tool_call_id = str(payload.get("tool_call_id") or "")
        if kind == "tool_call":
            pending[tool_call_id] = event
            continue
        if kind not in {"tool_return", "tool_error"}:
            continue
        start_event = pending.pop(tool_call_id, None)
        if start_event is None:
            unmatched.append({"side": "return", "tool_call_id": tool_call_id, "payload": payload})
            continue
        content = _coerce_text(payload.get("content"))
        pairs.append(
            CallPair(
                tool_call_id=tool_call_id,
                tool_name=str(start_event.payload.get("tool_name") or ""),
                source=str(start_event.payload.get("source") or ""),
                args=dict(start_event.payload.get("args") or {}),
                start=start_event.timestamp,
                end=event.timestamp,
                duration_sec=max((event.timestamp - start_event.timestamp).total_seconds(), 0.0),
                return_kind=kind,
                content=content,
                negative=(kind != "tool_return") or _is_negative_content(content),
            )
        )

    for tool_call_id, start_event in pending.items():
        unmatched.append({"side": "call", "tool_call_id": tool_call_id, "payload": start_event.payload})

    return pairs, unmatched


def pair_span_events(
    events: Iterable[LogEvent],
    *,
    start_kind: str,
    finish_kind: str,
    span_kind: str,
) -> list[SpanPair]:
    pending: dict[tuple[str, str], LogEvent] = {}
    spans: list[SpanPair] = []
    for event in sorted(events, key=lambda item: item.timestamp):
        payload = event.payload
        kind = str(payload.get("kind") or "")
        key = (str(payload.get("source") or ""), str(payload.get("work_item_id") or ""))
        if kind == start_kind:
            pending[key] = event
            continue
        if kind != finish_kind:
            continue
        start_event = pending.pop(key, None)
        if start_event is None:
            continue
        spans.append(
            SpanPair(
                kind=span_kind,
                source=key[0],
                work_item_id=key[1],
                start=start_event.timestamp,
                end=event.timestamp,
                duration_sec=max((event.timestamp - start_event.timestamp).total_seconds(), 0.0),
                payload=dict(payload or {}),
            )
        )
    return spans


def _mean(values: Iterable[float]) -> float | None:
    seq = [value for value in values if value is not None]
    if not seq:
        return None
    return sum(seq) / len(seq)


def _round(value: float | None, digits: int = 2) -> float | None:
    if value is None:
        return None
    return round(value, digits)


def summarize_events(events: list[LogEvent], pairs: list[CallPair], top_n: int) -> dict[str, Any]:
    if not events:
        return {"error": "No events parsed"}

    events = sorted(events, key=lambda event: event.timestamp)
    pairs = sorted(pairs, key=lambda pair: pair.start)

    kind_counts = Counter(str(event.payload.get("kind") or "") for event in events)
    source_counts = Counter(str(event.payload.get("source") or "") for event in events if event.payload.get("source"))
    tool_call_counts = Counter(pair.tool_name for pair in pairs)

    start = events[0].timestamp
    end = events[-1].timestamp
    total_runtime_sec = max((end - start).total_seconds(), 0.0)
    run_ids = sorted({event.run_id for event in events})
    stages = sorted({event.stage for event in events})

    per_tool: dict[str, dict[str, Any]] = {}
    grouped_by_tool: dict[str, list[CallPair]] = defaultdict(list)
    for pair in pairs:
        grouped_by_tool[pair.tool_name].append(pair)
    for tool_name, tool_pairs in grouped_by_tool.items():
        durations = [pair.duration_sec for pair in tool_pairs]
        negatives = [pair for pair in tool_pairs if pair.negative]
        per_tool[tool_name] = {
            "calls": len(tool_pairs),
            "total_duration_sec": _round(sum(durations)),
            "mean_duration_sec": _round(_mean(durations)),
            "max_duration_sec": _round(max(durations) if durations else 0.0),
            "negative_calls": len(negatives),
        }

    per_source: dict[str, dict[str, Any]] = {}
    grouped_by_source: dict[str, list[CallPair]] = defaultdict(list)
    for pair in pairs:
        grouped_by_source[pair.source].append(pair)
    for source, source_pairs in grouped_by_source.items():
        source_pairs = sorted(source_pairs, key=lambda pair: pair.start)
        first_start = source_pairs[0].start
        last_end = source_pairs[-1].end
        wall_span = max((last_end - first_start).total_seconds(), 0.0)
        active_time = sum(pair.duration_sec for pair in source_pairs)
        gaps = []
        previous_end = None
        for pair in source_pairs:
            if previous_end is not None:
                gap = max((pair.start - previous_end).total_seconds(), 0.0)
                if gap > 0:
                    gaps.append(gap)
            previous_end = pair.end
        per_source[source] = {
            "tool_calls": len(source_pairs),
            "wall_span_sec": _round(wall_span),
            "active_tool_time_sec": _round(active_time),
            "active_ratio": _round((active_time / wall_span) if wall_span else None, 3),
            "mean_gap_sec": _round(_mean(gaps)),
            "max_gap_sec": _round(max(gaps) if gaps else 0.0),
        }

    negative_calls = [
        {
            "timestamp": pair.end.isoformat(),
            "source": pair.source,
            "tool_name": pair.tool_name,
            "args": pair.args,
            "content": pair.content[:400],
            "duration_sec": _round(pair.duration_sec),
        }
        for pair in pairs
        if pair.negative
    ]

    duplicate_groups = []
    signature_map: dict[tuple[str, str, str], list[CallPair]] = defaultdict(list)
    for pair in pairs:
        signature = (pair.source, pair.tool_name, _json_signature(pair.args))
        signature_map[signature].append(pair)
    for (source, tool_name, args_sig), tool_pairs in signature_map.items():
        if len(tool_pairs) < 2:
            continue
        total_duration = sum(pair.duration_sec for pair in tool_pairs)
        duplicate_groups.append(
            {
                "source": source,
                "tool_name": tool_name,
                "args": json.loads(args_sig),
                "calls": len(tool_pairs),
                "duplicate_calls_beyond_first": len(tool_pairs) - 1,
                "total_duration_sec": _round(total_duration),
                "duplicate_duration_beyond_first_sec": _round(total_duration - tool_pairs[0].duration_sec),
                "negative_calls": sum(1 for pair in tool_pairs if pair.negative),
            }
        )
    duplicate_groups.sort(
        key=lambda item: (
            -int(item["duplicate_calls_beyond_first"]),
            -float(item["duplicate_duration_beyond_first_sec"] or 0.0),
        )
    )

    long_gaps = []
    for earlier, later in zip(events, events[1:]):
        gap = max((later.timestamp - earlier.timestamp).total_seconds(), 0.0)
        if gap <= 0:
            continue
        long_gaps.append(
            {
                "gap_sec": _round(gap),
                "from_timestamp": earlier.timestamp.isoformat(),
                "to_timestamp": later.timestamp.isoformat(),
                "from_kind": earlier.payload.get("kind"),
                "to_kind": later.payload.get("kind"),
                "from_source": earlier.payload.get("source"),
                "to_source": later.payload.get("source"),
            }
        )
    long_gaps.sort(key=lambda item: -float(item["gap_sec"] or 0.0))

    return {
        "path": None,
        "run_ids": run_ids,
        "stages": stages,
        "event_count": len(events),
        "paired_calls": len(pairs),
        "unmatched_calls": 0,
        "kinds": dict(kind_counts),
        "sources": dict(source_counts),
        "start_timestamp": start.isoformat(),
        "end_timestamp": end.isoformat(),
        "total_runtime_sec": _round(total_runtime_sec),
        "tool_call_counts_top": [
            {"tool_name": tool_name, "calls": count}
            for tool_name, count in tool_call_counts.most_common(top_n)
        ],
        "per_tool_top_by_duration": sorted(
            (
                {"tool_name": tool_name, **stats}
                for tool_name, stats in per_tool.items()
            ),
            key=lambda item: (-float(item["total_duration_sec"] or 0.0), -int(item["calls"])),
        )[:top_n],
        "per_source": per_source,
        "negative_calls": negative_calls[:top_n],
        "negative_call_count": len(negative_calls),
        "duplicate_groups_top": duplicate_groups[:top_n],
        "duplicate_group_count": len(duplicate_groups),
        "duplicate_calls_beyond_first_total": sum(
            int(item["duplicate_calls_beyond_first"]) for item in duplicate_groups
        ),
        "estimated_duplicate_duration_beyond_first_sec": _round(
            sum(float(item["duplicate_duration_beyond_first_sec"] or 0.0) for item in duplicate_groups)
        ),
        "long_gaps_top": long_gaps[:top_n],
        "all_long_gaps_over_10s_count": sum(1 for item in long_gaps if float(item["gap_sec"] or 0.0) >= 10.0),
    }


def build_summary(events: list[LogEvent], pairs: list[CallPair], unmatched: list[dict[str, Any]], log_path: Path, top_n: int) -> dict[str, Any]:
    summary = summarize_events(events, pairs, top_n)
    worker_spans = pair_span_events(
        events,
        start_kind="worker_assignment_start",
        finish_kind="worker_assignment_finish",
        span_kind="worker_assignment",
    )
    model_spans = pair_span_events(
        events,
        start_kind="model_run_start",
        finish_kind="model_run_finish",
        span_kind="model_run",
    )
    summary["path"] = str(log_path)
    summary["unmatched_calls"] = len(unmatched)
    summary["unmatched_examples"] = unmatched[:top_n]
    summary["worker_assignment_spans_top"] = [
        {
            "source": span.source,
            "work_item_id": span.work_item_id,
            "duration_sec": _round(span.duration_sec),
            "status": span.payload.get("status"),
        }
        for span in sorted(worker_spans, key=lambda item: -item.duration_sec)[:top_n]
    ]
    summary["worker_assignment_total_duration_sec"] = _round(sum(span.duration_sec for span in worker_spans))
    summary["model_run_spans_top"] = [
        {
            "source": span.source,
            "work_item_id": span.work_item_id,
            "duration_sec": _round(span.duration_sec),
            "status": span.payload.get("status"),
        }
        for span in sorted(model_spans, key=lambda item: -item.duration_sec)[:top_n]
    ]
    summary["model_run_total_duration_sec"] = _round(sum(span.duration_sec for span in model_spans))
    return summary


def render_markdown(summary: dict[str, Any]) -> str:
    if "error" in summary:
        return f"# Worker Log Summary\n\n- Error: `{summary['error']}`\n"

    lines = ["# Worker Log Summary", ""]
    lines.append(f"- Log: `{summary['path']}`")
    lines.append(f"- Run IDs: `{', '.join(summary['run_ids'])}`")
    lines.append(f"- Stages: `{', '.join(summary['stages'])}`")
    lines.append(f"- Runtime: `{summary['total_runtime_sec']}s`")
    lines.append(f"- Events: `{summary['event_count']}`")
    lines.append(f"- Paired tool calls: `{summary['paired_calls']}`")
    lines.append(f"- Unmatched tool events: `{summary['unmatched_calls']}`")
    lines.append(f"- Negative tool returns: `{summary['negative_call_count']}`")
    lines.append(
        f"- Duplicate calls beyond first: `{summary['duplicate_calls_beyond_first_total']}` "
        f"(estimated repeated active time `{summary['estimated_duplicate_duration_beyond_first_sec']}s`)"
    )
    lines.append("")

    lines.append("## Top Tool Counts")
    lines.append("")
    for item in summary["tool_call_counts_top"]:
        lines.append(f"- `{item['tool_name']}`: `{item['calls']}`")
    lines.append("")

    lines.append("## Slowest Tools")
    lines.append("")
    for item in summary["per_tool_top_by_duration"]:
        lines.append(
            f"- `{item['tool_name']}`: `{item['calls']}` calls, `{item['total_duration_sec']}s` total, "
            f"`{item['mean_duration_sec']}s` mean, `{item['max_duration_sec']}s` max, "
            f"`{item['negative_calls']}` negative"
        )
    lines.append("")

    lines.append("## Per-Worker Spans")
    lines.append("")
    for source, item in sorted(summary["per_source"].items()):
        lines.append(
            f"- `{source}`: `{item['tool_calls']}` calls, `{item['wall_span_sec']}s` wall span, "
            f"`{item['active_tool_time_sec']}s` active tool time, active ratio `{item['active_ratio']}`, "
            f"max gap `{item['max_gap_sec']}s`"
        )
    lines.append("")

    lines.append("## Duplicate Call Groups")
    lines.append("")
    for item in summary["duplicate_groups_top"]:
        lines.append(
            f"- `{item['source']}` `{item['tool_name']}` `{json.dumps(item['args'], sort_keys=True)}`: "
            f"`{item['calls']}` calls, `{item['duplicate_calls_beyond_first']}` repeats, "
            f"`{item['duplicate_duration_beyond_first_sec']}s` repeated active time"
        )
    lines.append("")

    lines.append("## Negative Calls")
    lines.append("")
    for item in summary["negative_calls"]:
        lines.append(
            f"- `{item['timestamp']}` `{item['source']}` `{item['tool_name']}` "
            f"`{json.dumps(item['args'], sort_keys=True)}` -> `{item['content']}`"
        )
    lines.append("")

    if summary.get("worker_assignment_spans_top"):
        lines.append("## Worker Assignment Durations")
        lines.append("")
        for item in summary["worker_assignment_spans_top"]:
            lines.append(
                f"- `{item['source']}` `{item['work_item_id']}`: `{item['duration_sec']}s` "
                f"(status `{item['status']}`)"
            )
        lines.append("")

    if summary.get("model_run_spans_top"):
        lines.append("## Model Run Durations")
        lines.append("")
        for item in summary["model_run_spans_top"]:
            lines.append(
                f"- `{item['source']}` `{item['work_item_id']}`: `{item['duration_sec']}s` "
                f"(status `{item['status']}`)"
            )
        lines.append("")

    lines.append("## Long Gaps")
    lines.append("")
    for item in summary["long_gaps_top"]:
        lines.append(
            f"- `{item['gap_sec']}s` from `{item['from_timestamp']}` ({item['from_source']}:{item['from_kind']}) "
            f"to `{item['to_timestamp']}` ({item['to_source']}:{item['to_kind']})"
        )
    lines.append("")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze a multi_agent_wf workers.log file.")
    parser.add_argument("log_path", type=Path, help="Path to workers.log")
    parser.add_argument("--top", type=int, default=10, help="Number of top rows to show per section")
    parser.add_argument("--json-out", type=Path, help="Optional path for machine-readable JSON summary")
    parser.add_argument("--md-out", type=Path, help="Optional path for Markdown summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    events = parse_worker_log(args.log_path)
    pairs, unmatched = pair_tool_events(events)
    summary = build_summary(events, pairs, unmatched, args.log_path, args.top)

    rendered = render_markdown(summary)
    print(rendered)

    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    if args.md_out:
        args.md_out.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

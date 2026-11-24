"""Supply-Chain Guardian - dual-mode entrypoint.

CLI:
  python main.py --repo ./targets/juice-shop --mode scan
  python main.py --repo ./targets/juice-shop --mode check-pkg --pkg reqeusts@1.0.0
  python main.py --repo ./targets/juice-shop --mode replay --commits 5
  python main.py --repo ./targets/juice-shop --mode daemon --interval 30 [--max-polls 3 --demo-drift]
  python main.py --repo ./targets/juice-shop --mode simulate-attack
Web dashboard (binds to 127.0.0.1 only unless --allow-remote):
  python main.py --mode serve --port 8000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse  # noqa: E402
from starlette.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402

from continuous_monitor import Engine  # noqa: E402
from models import (  # noqa: E402
    ChatRequest,
    CheckPkgRequest,
    DaemonToggleRequest,
    ReplayRequest,
    ScanRequest,
    SimulateRequest,
)
from orchestrator import LogBus  # noqa: E402


def default_repo() -> str:
    env = os.environ.get("SCG_DEFAULT_REPO")
    if env:
        return env
    local = PROJECT_ROOT / "targets" / "juice-shop"
    return str(local) if local.is_dir() else "/tmp/juice-shop"


# --------------------------------------------------------------------------- #
# FastAPI
# --------------------------------------------------------------------------- #
LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]", "::1"]


def create_app(engine: Engine, bus: LogBus, allowed_hosts: Optional[list] = None) -> FastAPI:
    app = FastAPI(title="Supply-Chain Guardian", version="1.0.0", docs_url="/api/docs", redoc_url=None)
    hosts = allowed_hosts or LOOPBACK_HOSTS
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)   # blocks DNS-rebinding

    @app.middleware("http")
    async def same_origin_and_headers(request: Request, call_next: Any) -> Any:
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin:
                host = origin.split("://", 1)[-1].split("/")[0].rsplit(":", 1)[0].strip("[]")
                if host not in [h.strip("[]") for h in hosts] and "*" not in hosts:
                    return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
            if not request.headers.get("content-type", "").startswith("application/json"):
                return JSONResponse({"detail": "application/json required"}, status_code=415)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def run(fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=f"not found: {exc}") from exc

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(PROJECT_ROOT / "static" / "index.html", media_type="text/html")

    @app.get("/api/config")
    async def config() -> dict:
        from orchestrator import LLMClient
        llm = LLMClient()
        active = llm.enabled and engine.use_llm
        return {"default_repo": default_repo(), "llm_provider": llm.provider if active else "none",
                "llm_model": llm.model if active else None, "offline": os.environ.get("SCG_OFFLINE") == "1"}

    @app.get("/api/result")
    async def result() -> Any:
        res = engine.refresh_result()
        return res.model_dump(mode="json") if res else {}

    @app.post("/api/scan")
    async def scan(req: ScanRequest) -> Any:
        res = await run(engine.scan, req.repo, req.use_llm, req.resolve_lockfile)
        return res.model_dump(mode="json")

    @app.post("/api/check-pkg")
    async def check_pkg(req: CheckPkgRequest) -> Any:
        res = await run(engine.check_pkg, req.repo, req.pkg)
        return {"admission": res.model_dump(mode="json"), "result": engine.refresh_result().model_dump(mode="json")}

    @app.post("/api/replay")
    async def replay(req: ReplayRequest) -> Any:
        res = await run(engine.replay, req.repo, req.commits)
        return {"replay": res.model_dump(mode="json"), "result": engine.refresh_result().model_dump(mode="json")}

    @app.post("/api/simulate-attack")
    async def simulate(req: SimulateRequest) -> Any:
        res = await run(engine.simulate_attack, req.repo)
        return res.model_dump(mode="json")

    @app.get("/api/daemon/status")
    async def daemon_status() -> Any:
        return engine.daemon.status.model_dump(mode="json")

    @app.post("/api/daemon/toggle")
    async def daemon_toggle(req: DaemonToggleRequest) -> Any:
        if engine.daemon.status.running:
            return engine.daemon.stop().model_dump(mode="json")
        try:
            from scanners import validate_repo_path
            validate_repo_path(req.repo)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return engine.daemon.start(req.repo, req.interval, req.demo_drift).model_dump(mode="json")

    @app.post("/api/chat")
    async def chat(req: ChatRequest) -> Any:
        if engine.orch is None:
            raise HTTPException(status_code=409, detail="run a scan first")
        res = await run(engine.orch.answer, req.message, req.session_id)
        return res.model_dump(mode="json")

    @app.get("/api/stream")
    async def stream(request: Request) -> StreamingResponse:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        def push(ev: Any) -> None:
            def put() -> None:
                if not queue.full():
                    queue.put_nowait(ev)
            loop.call_soon_threadsafe(put)

        unsubscribe = bus.subscribe(push)

        async def gen() -> AsyncIterator[str]:
            try:
                for ev in bus.history()[-150:]:
                    yield f"data: {ev.model_dump_json()}\n\n"
                while not await request.is_disconnected():
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=15)
                        yield f"data: {ev.model_dump_json()}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                unsubscribe()

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


# --------------------------------------------------------------------------- #
# CLI rendering
# --------------------------------------------------------------------------- #
def _console() -> Any:
    from rich.console import Console
    return Console()


def print_cards(cards: list, limit: int = 8) -> None:
    from rich.panel import Panel
    from rich.markup import escape
    con = _console()
    colour = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green"}
    for c in cards[:limit]:
        sev = c.finding.severity.value
        math = " ".join([f"{c.risk.base}"] + [f"{d.value:+d}" for d in c.risk.deltas]) + f" = {c.risk.total}"
        v = c.validation
        body = (f"[bold]1. Finding[/] {escape(c.finding.title)}\n   purl: {escape(str(c.finding.purl))}  "
                f"ids: {escape(', '.join(c.finding.advisory_ids[:3]))}\n"
                f"[bold]2. Location[/] {escape(c.location.local_file)}:{c.location.local_line}\n"
                f"[dim]{escape(c.location.code_snippet[:500])}[/]\n"
                f"[bold]3. Attack path[/] (depth {c.attack_path.call_chain_depth})\n   " +
                "\n   ".join(escape(h) for h in c.attack_path.hops[:6]) +
                f"\n[bold]4. Risk Elo[/] {math} -> {sev}\n   " +
                "\n   ".join(escape(f"{d.value:+d} {d.label}") for d in c.risk.deltas) +
                f"\n[bold]5. Remediation[/] {escape(c.remediation.summary)}\n   $ {escape(c.remediation.fix_command)}\n"
                f"[dim]{escape(c.narrative[:400])}[/]\n"
                f"Validator: {'[green]PASSED[/]' if v and v.passed else '[red]FAILED[/]'} (author={c.author}"
                f"{', fallback' if v and v.fell_back_to_deterministic else ''})")
        con.print(Panel(body, title=f"[{colour[sev]}]{c.finding.finding_id}  {sev}  Elo {c.risk.total}[/]",
                        border_style=colour[sev]))


def print_scan(res: Any) -> None:
    from rich.table import Table
    from rich.markup import escape
    con = _console()
    k = res.kpis
    con.print(f"\n[bold]Components[/] {k.total_components}   [bold]Raw alerts[/] {k.raw_scanner_alerts}   "
              f"[bold red]Actionable critical[/] {k.actionable_critical}   [bold green]Downgraded noise[/] {k.downgraded_noise}"
              f"   (sbom={res.sbom_source}, advisories={res.vuln_source})")
    for n in res.notes:
        con.print(f"[yellow]note:[/] {escape(n)}")
    t = Table(title="Findings (Risk Elo, highest first)", show_lines=False)
    for col in ("ID", "Elo", "Severity", "Reach", "Title"):
        t.add_column(col)
    for f in res.findings[:40]:
        reach = {True: "called", False: "not called", None: "-"}[f.elo.factors.is_symbol_called]
        t.add_row(f.id, str(f.elo.total), f.elo.severity.value, reach, escape(f.title[:90]))
    con.print(t)
    info = [a for a in res.anomalies if not a.scored]
    if info:
        con.print("[dim]Informational (not scored): " + "; ".join(escape(f"{a.file}:{a.line} {a.title}") for a in info[:8]) + "[/]")
    print_cards(res.cards, limit=5)


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Continuous agentic software supply-chain security (read-only).")
    p.add_argument("--repo", default=default_repo(), help="path to the target repository (read-only)")
    p.add_argument("--mode", default="scan", choices=["scan", "check-pkg", "replay", "daemon", "simulate-attack", "serve"])
    p.add_argument("--pkg", help="candidate package for check-pkg, e.g. reqeusts@1.0.0 or pypi:requests==2.31.0")
    p.add_argument("--commits", type=int, default=5)
    p.add_argument("--interval", type=int, default=30)
    p.add_argument("--max-polls", type=int, default=None, help="daemon: stop after N polls")
    p.add_argument("--demo-drift", action="store_true", help="daemon: inject one clearly-labelled synthetic advisory on poll 2")
    p.add_argument("--no-llm", action="store_true", help="deterministic triage only; nothing is sent to an LLM provider")
    p.add_argument("--offline", action="store_true", help="no network: no OSV / registry lookups (demo advisories)")
    p.add_argument("--resolve-lockfile", action="store_true",
                   help="opt-in: resolve a lockfile from registry metadata (npm --package-lock-only --ignore-scripts in a temp dir)")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--keep-sandbox", action="store_true", help="simulate-attack: keep the temp sandbox for inspection")
    p.add_argument("--json-out", help="write the result as JSON to this path")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--allow-remote", action="store_true",
                   help="allow binding to a non-loopback interface (the API can read repository files: think twice)")
    args = p.parse_args(argv)
    if args.offline:
        os.environ["SCG_OFFLINE"] = "1"

    bus = LogBus(console=True)
    engine = Engine(bus)
    engine.use_llm = not args.no_llm

    if args.mode == "serve":
        import uvicorn
        if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
            print("Refusing to bind to a non-loopback address without --allow-remote.", file=sys.stderr)
            return 2
        hosts = LOOPBACK_HOSTS + ([args.host] if args.allow_remote else [])
        app = create_app(engine, bus, hosts)
        print(f"Dashboard: http://127.0.0.1:{args.port}/   (default repo: {args.repo})")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return 0

    result: Any
    try:
        if args.mode == "scan":
            result = engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile,
                                 use_cache=not args.no_cache)
            print_scan(result)
        elif args.mode == "check-pkg":
            if not args.pkg:
                p.error("--pkg is required for check-pkg")
            engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile)
            result = engine.check_pkg(args.repo, args.pkg)
            con = _console()
            colour = "red" if result.decision.value == "BLOCKED" else "green"
            con.print(f"\n[bold {colour}]{result.decision.value}[/] {result.package}@{result.version} "
                      f"(metadata: {result.metadata_source})")
            for s in result.signals:
                con.print(f"  {'[red]x[/]' if s.triggered and s.hard_block else ('[yellow]![/]' if s.triggered else '[green]ok[/]')} "
                          f"{s.name}: {s.detail}")
            for e in result.errors:
                con.print(f"  [dim]{e}[/]")
            if result.card:
                print_cards([result.card])
        elif args.mode == "replay":
            result = engine.replay(args.repo, args.commits)
            con = _console()
            for c in result.commits:
                con.print(f"[bold]{c.sha}[/] {c.subject[:70]}  +{len(c.added)} -{len(c.removed)} ~{len(c.changed)}  "
                          f"anomalies={len(c.anomalies)}  gate={[a.decision.value for a in c.admissions]}  triaged={c.triaged}")
            for n in result.notes:
                con.print(f"[yellow]{n}[/]")
        elif args.mode == "daemon":
            engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile)
            try:
                asyncio.run(engine.daemon.run_foreground(args.repo, args.interval, args.max_polls, args.demo_drift))
            except KeyboardInterrupt:
                pass
            result = engine.daemon.status
            print(result.model_dump_json(indent=2))
        else:  # simulate-attack
            result = engine.simulate_attack(args.repo, keep_sandbox=args.keep_sandbox)
            con = _console()
            print_cards(result.cards)
            con.print(f"\n[bold {'green' if result.blocked else 'red'}]"
                      f"{'ATTACK INTERCEPTED AND BLOCKED' if result.blocked else 'ATTACK NOT FULLY BLOCKED'}[/] "
                      f"max Risk Elo {result.max_elo}; sandbox removed={result.sandbox_removed}")
            for n in result.safety_notes:
                con.print(f"[dim]safety: {n}[/]")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
    if args.mode == "check-pkg" and result.decision.value == "BLOCKED":
        return 3   # non-zero so CI / pre-commit hooks can gate on it
    if args.mode == "simulate-attack" and not result.blocked:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

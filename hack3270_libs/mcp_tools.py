"""
MCP tool registration for Phase 3 attacks.

Wires the implemented attack modules into hackterm_core.ApiServer.
The API is line-based TCP on :31337 — each handler takes a string
arg and returns a string response. JSON for structured data.

Spec §3.2-§3.5 list per-attack tool signatures. This module collects
them in one place so the GUI/CLI just calls register_all() once.

MCP-first principle (spec §5 Phase 3 note): test attacks via these
handlers BEFORE building GUI tabs.
"""
import json

from hackterm_core import QueryLies


_VALID_INDFILE_MODES = {"carbon_copy", "inject", "alert"}


def register_all(api_server, attacks: dict) -> None:
    """Register all Phase 3 attack handlers on the ApiServer.

    Args:
      api_server: hackterm_core.ApiServer instance
      attacks: dict with keys 'esm', 'lu', 'qr', 'indfile'
               (the four attack objects, already attached to daemon)

    Each handler: (args: str) -> str. Errors return "ERROR: <msg>"
    rather than raising — the API server is a thin TCP shim and can't
    propagate exceptions usefully.
    """
    esm = attacks["esm"]
    lu = attacks["lu"]
    qr = attacks["qr"]
    indfile = attacks["indfile"]

    # --- ESM passive fingerprinter ------------------------------------

    def esm_get_findings(_args: str) -> str:
        return json.dumps(esm.findings)

    api_server.register("esm_get_findings", esm_get_findings)

    # --- LU-name spoofer ----------------------------------------------

    def lu_spoof_single(args: str) -> str:
        name = args.strip()
        if not name:
            return "ERROR: usage: lu_spoof_single <luname>"
        lu.set_target(name)
        return "OK"

    def lu_spoof_next(_args: str) -> str:
        nxt = lu.next_lu()
        return nxt if nxt else "DONE"

    def lu_get_harvested(_args: str) -> str:
        return json.dumps(sorted(lu.harvested))

    def lu_get_results(_args: str) -> str:
        # results is list[tuple[str, str]] — JSON has no tuples, use lists
        return json.dumps([list(r) for r in lu.results])

    api_server.register("lu_spoof_single", lu_spoof_single)
    api_server.register("lu_spoof_next", lu_spoof_next)
    api_server.register("lu_get_harvested", lu_get_harvested)
    api_server.register("lu_get_results", lu_get_results)

    # --- Query Reply liar ---------------------------------------------

    def qr_arm(args: str) -> str:
        try:
            d = json.loads(args) if args.strip() else {}
        except json.JSONDecodeError as e:
            return f"ERROR: bad JSON: {e}"
        try:
            lies = QueryLies(
                alt_rows=d.get("alt_rows"),
                alt_cols=d.get("alt_cols"),
                deny_color=d.get("deny_color", False),
                deny_highlighting=d.get("deny_highlighting", False),
                deny_graphics=d.get("deny_graphics", False),
                rpq_name=d.get("rpq_name"),
            )
        except (TypeError, AttributeError) as e:
            return f"ERROR: invalid lies spec: {e}"
        qr.arm(lies)
        return "OK"

    def qr_disarm(_args: str) -> str:
        qr.disarm()
        return "OK"

    api_server.register("qr_arm", qr_arm)
    api_server.register("qr_disarm", qr_disarm)

    # --- IND$FILE detector --------------------------------------------

    def indfile_set_mode(args: str) -> str:
        mode = args.strip()
        if mode not in _VALID_INDFILE_MODES:
            return (f"ERROR: mode must be one of "
                    f"{sorted(_VALID_INDFILE_MODES)}")
        indfile.mode = mode
        return "OK"

    def indfile_get_captures(_args: str) -> str:
        return json.dumps(indfile.captures)

    api_server.register("indfile_set_mode", indfile_set_mode)
    api_server.register("indfile_get_captures", indfile_get_captures)

    # --- State fuzzer (optional — Tasks 6-8) --------------------------
    # Use .get() not [] so existing callers without a fuzzer still work.

    fuzzer = attacks.get("fuzzer")
    if fuzzer is not None:

        def flow_record_start(args: str) -> str:
            name = args.strip() or "unnamed"
            fuzzer.start_recording(name)
            return "OK"

        def flow_record_stop(_args: str) -> str:
            return str(fuzzer.stop_recording())

        def flow_analyze(args: str) -> str:
            try:
                flow_id = int(args.strip())
            except ValueError:
                return "ERROR: usage: flow_analyze <flow_id>"
            from dataclasses import asdict
            return json.dumps([asdict(t) for t in fuzzer.analyze(flow_id)])

        def flow_list_mutations(_args: str) -> str:
            return json.dumps(["length_plus_1", "length_double",
                               "type_confusion", "extra_sba", "step_swap"])

        api_server.register("flow_record_start", flow_record_start)
        api_server.register("flow_record_stop", flow_record_stop)
        api_server.register("flow_analyze", flow_analyze)
        api_server.register("flow_list_mutations", flow_list_mutations)

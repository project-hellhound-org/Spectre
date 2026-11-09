"""
Dashboard backend.

Changes for this iteration:
  - Takes the `collector` itself (not a scope snapshot), so /api/scope
    always reflects the live TargetScope — including after a `swap`,
    whether that swap came from the CLI REPL or from this dashboard's
    own /api/swap endpoint. TargetScope.replace_with() mutates in place,
    so this needs no extra wiring.
  - /api/swap lets the dashboard itself change targets, independent of
    the CLI session that launched it — matches the "dashboard runs
    independently" requirement: you can drive it entirely from the
    browser once it's up.
  - /api/events accepts ?min_severity= so the redesigned frontend can
    request a "priority findings only" view (SUSPICIOUS and above)
    separately from the full recent-activity log.
  - debug=False by default (unchanged from the previous iteration —
    the original tool ran Flask's debug/interactive debugger
    unconditionally, a real risk if the port is ever reachable beyond
    localhost).
"""
from flask import Flask, jsonify, render_template, request

from core.target import TargetScope
from core.target_parser import build_scope

SEVERITY_ORDER = ["BENIGN", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL"]


def create_app(store, collector):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("index.html", scope=collector.target_scope.describe())

    @app.route("/api/scope")
    def api_scope():
        return jsonify({
            "scope": collector.target_scope.describe(),
            "restricted": collector.target_scope.is_restricted,
            "capturing": collector.is_running(),
        })

    @app.route("/api/events")
    def api_events():
        n = request.args.get("limit", 300, type=int)
        min_severity = request.args.get("min_severity")
        events = list(reversed(store.recent(n)))
        if min_severity and min_severity in SEVERITY_ORDER:
            floor = SEVERITY_ORDER.index(min_severity)
            events = [e for e in events if SEVERITY_ORDER.index(e.get("severity", "BENIGN")) >= floor]
        return jsonify(events)

    @app.route("/api/summary")
    def api_summary():
        return jsonify(store.summary())

    @app.route("/api/swap", methods=["POST"])
    def api_swap():
        payload = request.get_json(silent=True) or {}
        raw_targets = payload.get("targets", [])
        if isinstance(raw_targets, str):
            raw_targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

        try:
            scope_kwargs = build_scope(raw_targets)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        new_scope = TargetScope(**scope_kwargs)
        collector.swap_target(new_scope)
        return jsonify({"ok": True, "scope": collector.target_scope.describe()})

    return app

"""Flask dashboard application for Bug Bounty Recon Framework."""

import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

from core.config import Config
from core.storage import Storage


def create_app(config: Config = None) -> Flask:
    """Create and configure the Flask dashboard app."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    if not config:
        config = Config()

    db_path = config.get("database", "path", default="data/recon.db")
    storage = Storage(db_path)

    # --- Routes ---

    @app.route("/")
    def index():
        """Dashboard home page with statistics."""
        stats = storage.get_statistics()
        return render_template("index.html", stats=stats)

    @app.route("/reports")
    def reports():
        """Browse and search reports."""
        category = request.args.get("category")
        platform = request.args.get("platform")
        severity = request.args.get("severity")
        keyword = request.args.get("q")
        page = int(request.args.get("page", 1))
        per_page = 25

        results = storage.search_reports(
            category=category,
            platform=platform,
            severity=severity,
            keyword=keyword,
            limit=per_page,
            offset=(page - 1) * per_page,
        )

        total = storage.get_report_count(category=category)
        total_pages = (total + per_page - 1) // per_page

        return render_template(
            "reports.html",
            reports=results,
            total=total,
            page=page,
            total_pages=total_pages,
            category=category,
            platform=platform,
            severity=severity,
            keyword=keyword,
        )

    @app.route("/reports/<report_id>")
    def report_detail(report_id):
        """View single report details."""
        report = storage.get_report(report_id)
        if not report:
            return render_template("404.html"), 404
        # Parse raw_data JSON
        raw_data = {}
        if report.get("raw_data"):
            try:
                raw_data = json.loads(report["raw_data"])
            except (json.JSONDecodeError, TypeError):
                pass
        return render_template("report_detail.html", report=report, raw_data=raw_data)

    @app.route("/payloads")
    def payloads():
        """Browse payloads by category."""
        category = request.args.get("category")
        results = storage.get_payloads(category=category, limit=200)
        categories = config.categories
        return render_template("payloads.html", payloads=results, categories=categories, selected=category)

    @app.route("/parameters")
    def parameters():
        """View top attacked parameters."""
        category = request.args.get("category")
        results = storage.get_top_parameters(category=category, limit=50)
        categories = config.categories
        return render_template("parameters.html", parameters=results, categories=categories, selected=category)

    @app.route("/patterns")
    def patterns():
        """View detected patterns."""
        category = request.args.get("category")
        results = storage.get_patterns(category=category)
        categories = config.categories
        return render_template("patterns.html", patterns=results, categories=categories, selected=category)

    @app.route("/statistics")
    def statistics():
        """Detailed statistics page."""
        stats = storage.get_statistics()
        return render_template("statistics.html", stats=stats)

    # --- API Endpoints ---

    @app.route("/api/reports")
    def api_reports():
        """API: Get reports with filters."""
        category = request.args.get("category")
        platform = request.args.get("platform")
        severity = request.args.get("severity")
        keyword = request.args.get("q")
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))

        results = storage.search_reports(
            category=category, platform=platform, severity=severity,
            keyword=keyword, limit=limit, offset=offset,
        )
        return jsonify({"results": results, "total": storage.get_report_count(category)})

    @app.route("/api/stats")
    def api_stats():
        """API: Get statistics."""
        return jsonify(storage.get_statistics())

    @app.route("/api/payloads/<category>")
    def api_payloads(category):
        """API: Get payloads for category."""
        results = storage.get_payloads(category=category)
        return jsonify({"category": category, "payloads": results})

    @app.route("/api/export")
    def api_export():
        """API: Export all data as JSON."""
        data = {
            "statistics": storage.get_statistics(),
            "reports": storage.search_reports(limit=10000),
        }
        return jsonify(data)

    return app


def run_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Run the dashboard server."""
    config = Config()
    app = create_app(config)
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard(debug=True)

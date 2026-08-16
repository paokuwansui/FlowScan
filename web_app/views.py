"""页面视图路由:资产截图/图标 + xray 报告。"""
import json
import os
from datetime import datetime

from flask import Response, render_template, request

from flowscan.utils import project_root

from ._common import login_required
from ._helpers import xray_load_findings


def register(app):
    @app.route("/xray-report")
    @login_required
    def xray_report():
        report_path = os.path.join(project_root(), "reports", "xray_out.html")
        # 空文件/残留占位视为无报告，避免渲染一个空白 iframe
        html_exists = os.path.isfile(report_path) and os.path.getsize(report_path) > 0
        size = 0
        mtime = ""
        if html_exists:
            size = os.path.getsize(report_path)
            mtime = datetime.fromtimestamp(os.path.getmtime(report_path)).strftime("%Y-%m-%d %H:%M:%S")
        findings = xray_load_findings()
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in sev_counts:
                sev_counts[sev] += 1
        tab = request.args.get("tab", "json" if findings else "html")
        if tab not in ("json", "html"):
            tab = "json" if findings else "html"
        return render_template(
            "xray_report.html",
            html_exists=html_exists, size=size, mtime=mtime,
            findings=findings, sev_counts=sev_counts, tab=tab,
        )

    @app.route("/xray-report/raw")
    @login_required
    def xray_report_raw():
        report_path = os.path.join(project_root(), "reports", "xray_out.html")
        if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
            return Response(
                "<html><head><meta charset='utf-8'></head><body style='font-family:sans-serif;padding:2rem;'>"
                "<h2>尚未生成 xray 报告</h2>"
                "<p>xray 被动代理运行时会在 reports/ 目录生成 xray_out.html。</p>"
                "</body></html>",
                mimetype="text/html; charset=utf-8",
                status=404,
            )
        with open(report_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return Response(content, mimetype="text/html; charset=utf-8")

    @app.route("/xray-report/json")
    @login_required
    def xray_report_json():
        """原始 xray JSON 报告(供前端/外部程序/下载)。"""
        from ._helpers import xray_json_paths
        for path in xray_json_paths():
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                return Response(content, mimetype="application/json; charset=utf-8")
        return Response(
            json.dumps({"ok": False, "error": "reports/xray_out.json 不存在"}, ensure_ascii=False),
            mimetype="application/json; charset=utf-8",
            status=404,
        )

    @app.route("/screenshots")
    @login_required
    def screenshots():
        redis = app.config["get_redis"]()
        def read_image_events(event_type):
            fps = redis.conn.smembers(f"fs3:events:type:{event_type}") or []
            items = []
            for fp in sorted(fps):
                event = redis.get_event(fp)
                if not event:
                    continue
                try:
                    data = json.loads(event.get("value", "{}"))
                except Exception:
                    continue
                items.append({
                    "url": data.get("url", ""),
                    "path": data.get("path", ""),
                    "b64": data.get("b64", ""),
                    "mime": data.get("mime", "image/png"),
                    "created_at": event.get("created_at", ""),
                })
            items.sort(key=lambda s: s.get("created_at", ""), reverse=True)
            return items
        shots = read_image_events("SCREENSHOT")
        icons = read_image_events("ICON")
        tab = request.args.get("tab", "screenshot")
        if tab not in ("screenshot", "icon"):
            tab = "screenshot"
        return render_template("screenshots.html", shots=shots, icons=icons, tab=tab)

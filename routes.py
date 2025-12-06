from flask import render_template, request
from services import get_vulns, get_bounty

cached_vulns = None  # 初回だけAPI呼び出し

def fetch_vulns():
    global cached_vulns
    if cached_vulns is None:
        cached_vulns = get_bounty(get_vulns())
    return cached_vulns

def register_routes(app):
    @app.route("/")
    def welcome():
        sort = request.args.get("sort", "installs")
        word = (request.args.get("q") or "").strip()
        vulns = fetch_vulns()
        if word:
            word_lower = word.lower()
            vulns = [v for v in vulns if word_lower in (v.get("title") or "").lower()]
        keymap = {
            "installs": lambda v: v.get("install", 0) or 0,
            "bounty": lambda v: v.get("bounty", 0) or 0,
            "newest": lambda v: v.get("newest", 0) or 0,
        } 
        vulns_sorted = sorted(vulns, key=keymap.get(sort, keymap["installs"]), reverse=True)
        return render_template("index.html", insert_something=vulns_sorted, sort=sort)
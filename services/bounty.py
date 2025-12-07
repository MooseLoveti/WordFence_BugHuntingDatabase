import re
from pathlib import Path

AUTH_PRIORITY = [
    "No Authentication",
    "Low-Level Authentication",
    "Mid-Level Authentication",
    "High-Level Authentication",
]

CWE_TO_CATEGORY = {
    79: "Stored Cross-Site Scripting",  # XSS はすべて Stored と扱う
    352: "Cross-Site Request Forgery",
    862: "Authentication Bypass to Admin",
    89: "SQL Injection",
    434: "Arbitrary File Upload",
    200: "Sensitive Information Disclosure",
    98: "Remote Code Execution/Code Injection",
    502: "Remote Code Execution/Code Injection",
    22: "Arbitrary File Download/Read",
    639: "Authentication Bypass to Admin",
    94: "Remote Code Execution/Code Injection",
    918: "Server-Side Request Forgery",
    269: "Authentication Bypass to Admin",
    284: "Authentication Bypass to Admin",
    285: "Authentication Bypass to Admin",
    601: "Cross-Site Request Forgery",
    288: "Authentication Bypass to Admin",
    20: "Arbitrary Options Update",
    266: "Authentication Bypass to Admin",
    287: "Authentication Bypass to Admin",
    863: "Authentication Bypass to Admin",
    74: "Arbitrary Options Update",
    73: "Arbitrary File Download/Read",
    400: "Denial of Service",
    532: "Sensitive Information Disclosure",
    693: "Authentication Bypass to Admin",
    80: "Cross-Site Scripting",
    78: "Remote Code Execution/Code Injection",
    306: "Authentication Bypass to Admin",
    345: "Sensitive Information Disclosure",
    640: "Sensitive Information Disclosure",
    77: "Remote Code Execution/Code Injection",
    87: "Cross-Site Scripting",
    611: "Arbitrary File Download/Read",
    922: "Sensitive Information Disclosure",
    506: "Remote Code Execution/Code Injection",
    321: "Sensitive Information Disclosure",
    798: "Sensitive Information Disclosure",
    95: "Remote Code Execution/Code Injection",
    201: "Sensitive Information Disclosure",
    202: "Sensitive Information Disclosure",
    204: "Sensitive Information Disclosure",
    538: "Sensitive Information Disclosure",
    915: "Arbitrary Options Update",
    1395: "Dependency Confusion",
    286: "Authentication Bypass to Admin",
    290: "Authentication Bypass to Admin",
    307: "Authentication Bypass to Admin",
    807: "Authentication Bypass to Admin",
    35: "Arbitrary File Download/Read",
    116: "Cross-Site Scripting",
    256: "Sensitive Information Disclosure",
    261: "Sensitive Information Disclosure",
    280: "Authentication Bypass to Admin",
    703: "Denial of Service",
    1230: "Sensitive Information Disclosure",
    88: "Remote Code Execution/Code Injection",
    113: "Cross-Site Scripting",
    117: "Sensitive Information Disclosure",
    230: "Sensitive Information Disclosure",
    259: "Sensitive Information Disclosure",
    327: "Sensitive Information Disclosure",
    347: "Authentication Bypass to Admin",
    441: "Authentication Bypass to Admin",
    522: "Sensitive Information Disclosure",
    548: "Sensitive Information Disclosure",
    692: "Cross-Site Scripting",
    843: "Authentication Bypass to Admin",
    1021: "Cross-Site Request Forgery",
    1022: "Cross-Site Request Forgery",
    1321: "Arbitrary Options Update",
    24: "Arbitrary File Download/Read",
    25: "Arbitrary File Download/Read",
    75: "Cross-Site Scripting",
    90: "LDAP Injection",
    96: "Remote Code Execution/Code Injection",
    219: "Sensitive Information Disclosure",
    272: "Authentication Bypass to Admin",
    291: "Authentication Bypass to Admin",
    303: "Authentication Bypass to Admin",
    304: "Authentication Bypass to Admin",
    312: "Sensitive Information Disclosure",
    340: "Sensitive Information Disclosure",
    444: "Cross-Site Request Forgery",
    494: "Remote Code Execution/Code Injection",
    524: "Sensitive Information Disclosure",
    530: "Sensitive Information Disclosure",
    564: "SQL Injection",
    610: "Arbitrary File Download/Read",
    613: "Authentication Bypass to Admin",
    614: "Sensitive Information Disclosure",
    636: "Authentication Bypass to Admin",
    672: "Denial of Service",
    681: "Sensitive Information Disclosure",
    732: "Authentication Bypass to Admin",
    757: "Authentication Bypass to Admin",
    759: "Sensitive Information Disclosure",
    776: "Denial of Service",
    784: "Authentication Bypass to Admin",
    799: "Denial of Service",
    829: "Remote Code Execution/Code Injection",
    916: "Sensitive Information Disclosure",
    1188: "Authentication Bypass to Admin",
    1229: "Sensitive Information Disclosure",
    1250: "Arbitrary Options Update",
    1287: "Arbitrary Options Update",
    1390: "Authentication Bypass to Admin",
}

def _load_bounty_table():
    bounty_file = Path(__file__).resolve().parents[1] / "calculate" / "bountydata.txt"
    range_pattern = re.compile(r"^(<\d+|\d+-\d+|\d+\+)$")
    table = []
    if not bounty_file.exists():
        return table
    with bounty_file.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            parts = line.split()
            try:
                reward = int(parts[-1])
            except (IndexError, ValueError):
                continue
            tokens = parts[:-1]
            range_idx = next((i for i, t in enumerate(tokens) if range_pattern.match(t)), None)
            if range_idx is None or range_idx == 0:
                continue
            install_range = tokens[range_idx]
            category = " ".join(tokens[:range_idx])
            auth = " ".join(tokens[range_idx + 1 :]).strip()
            table.append({"category": category, "install_range": install_range, "auth": auth, "bounty": reward})
    return table

BOUNTY_TABLE = _load_bounty_table()

def _range_contains(token: str, installs: int) -> bool:
    installs = installs or 0
    if token.startswith("<"):
        return installs < int(token[1:])
    if token.endswith("+"):
        return installs >= int(token[:-1])
    low, high = map(int, token.split("-"))
    return low <= installs <= high

def _detect_auth(text: str) -> str | None:
    t = text.lower()
    if "unauthenticated" in t or "no authentication" in t:
        return "No Authentication"
    if "subscriber+" in t:
        return "Low-Level Authentication"
    if "contributor+" in t or "author+" in t:
        return "Mid-Level Authentication"
    if "admin" in t or "administrator" in t or "authenticated" in t or "editor+" in t:
        return "High-Level Authentication"
    return None

def _detect_category_from_cwe(cid):
    return CWE_TO_CATEGORY.get(cid)

def get_bounty(vulns):
    for v in vulns:
        text = f"{v.get('title','')}"
        category = _detect_category_from_cwe((v.get("cwe") or {}).get("id"))
        auth = _detect_auth(text)
        installs = v.get("install") or 0

        bounty = 0
        if category and auth is not None:
            same_cat = [r for r in BOUNTY_TABLE if r["category"].lower() == category.lower()]
            same_range = [r for r in same_cat if _range_contains(r["install_range"], installs)]
            same_auth = [r for r in same_range if r["auth"] == auth]
            if same_auth:
                bounty = same_auth[0]["bounty"]
        v["bounty"] = bounty
    return vulns

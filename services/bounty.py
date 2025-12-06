import re
from pathlib import Path

# bountydata.txt をパースして保持する簡易テーブル
def _load_bounty_table():
    bounty_file = Path(__file__).resolve().parents[1] / "Calculator" / "bountydata.txt"
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
            range_idx = None
            for i, token in enumerate(tokens):
                if range_pattern.match(token):
                    range_idx = i
                    break
            if range_idx is None or range_idx == 0:
                continue

            install_range = tokens[range_idx]
            category = " ".join(tokens[:range_idx])
            auth = " ".join(tokens[range_idx + 1 :]).strip()
            table.append(
                {
                    "category": category,
                    "install_range": install_range,
                    "auth": auth,
                    "bounty": reward,
                }
            )
    return table


BOUNTY_TABLE = _load_bounty_table()

def get_bounty(vulns):
    # 今は報奨金を計算せずそのまま返す。BOUNTY_TABLE を利用して今後加点することを想定。
    return vulns

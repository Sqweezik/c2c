#!/usr/bin/env python3
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ACCESS = Path('log_dist/src/access.log')

# Common log format-ish:
# ip - - [11/Jan/2026:12:23:15 +0000] "GET /path HTTP/1.1" 302 419 "ref" "ua"
LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"$'
)


def parse_ts(ts: str) -> datetime:
    # 11/Jan/2026:12:23:15 +0000
    return datetime.strptime(ts, '%d/%b/%Y:%H:%M:%S %z')


def extract_sqlmap_blind_string(rows: list[dict], column: str) -> str | None:
    """
    Reconstruct a string exfiltrated by sqlmap-style blind SQLi using a binary-search
    sequence that ends with checks like:
      ORD(MID((SELECT ... <column> ...),<pos>,1))!=<ascii>
    We can infer the character from the last '!=' check observed for each position.
    """
    import urllib.parse

    # Example decoded fragment:
    # ... IF(ORD(MID((SELECT IFNULL(CAST(user_email AS NCHAR),0x20) FROM wordpress.wp_users ...),1,1))!=97,0,1)
    rx = re.compile(
        rf'ORD\(MID\(\(SELECT .*?{re.escape(column)}.*?\),(\d+),1\)\)\s*([<>]=?|!=)\s*(\d+)',
        re.IGNORECASE,
    )

    per_pos: dict[int, list[tuple[int, str, int]]] = defaultdict(list)

    for i, r in enumerate(rows):
        if r['method'] != 'GET':
            continue
        if '/wp-json/layart/v1/fonts' not in r['path']:
            continue
        if 'family=' not in r['path']:
            continue

        # Pull and decode `family=` payload.
        try:
            _, qs = r['path'].split('?', 1)
        except ValueError:
            continue
        if not qs.startswith('family='):
            continue

        decoded = urllib.parse.unquote(qs[len('family=') :])
        m = rx.search(decoded)
        if not m:
            continue

        pos = int(m.group(1))
        op = m.group(2)
        val = int(m.group(3))
        per_pos[pos].append((i, op, val))

    if not per_pos:
        return None

    # Use the last '!=' check per position as the extracted character (sqlmap ends with that).
    out = []
    for pos in sorted(per_pos):
        items = per_pos[pos]
        ne = [it for it in items if it[1] == '!=']
        if not ne:
            break
        out.append(chr(ne[-1][2]))

    return ''.join(out) if out else None


def main() -> None:
    rows = []
    bad = 0
    for line in ACCESS.read_text(errors='ignore').splitlines():
        m = LINE_RE.match(line)
        if not m:
            bad += 1
            continue
        d = m.groupdict()
        d['status'] = int(d['status'])
        d['ts_dt'] = parse_ts(d['ts'])
        rows.append(d)

    print(f'parsed={len(rows)} bad={bad}')

    ips = Counter(r['ip'] for r in rows)
    print('top ips:')
    for ip, n in ips.most_common(10):
        first = min(r['ts_dt'] for r in rows if r['ip'] == ip)
        last = max(r['ts_dt'] for r in rows if r['ip'] == ip)
        print(f'- {ip}: {n} ({first} .. {last})')

    def show(title, pred, limit=20):
        print(f'\n{title}:')
        out = [r for r in rows if pred(r)]
        for r in out[:limit]:
            print(f"- {r['ts']} {r['ip']} {r['method']} {r['path']} {r['status']} ua={r['ua']}")
        print(f'count={len(out)}')

    show('wordpress install', lambda r: 'wp-admin/install.php' in r['path'])
    show('plugin upload', lambda r: 'wp-admin/update.php' in r['path'] and 'upload-plugin' in r['path'])
    show('plugin activate', lambda r: 'wp-admin/plugins.php?action=activate' in r['path'])
    show('sqlmap hits', lambda r: 'sqlmap' in r['ua'].lower())
    show('layart fonts', lambda r: '/wp-json/layart/v1/fonts' in r['path'])
    show('wp-login POST', lambda r: r['path'].startswith('/wp-login.php') and r['method'] == 'POST')
    show('wp-login success-ish (302)', lambda r: r['path'].startswith('/wp-login.php') and r['method'] == 'POST' and r['status'] == 302)
    show('deface slug hacked-lolll', lambda r: '/hacked-lolll/' in r['path'])

    # Q3-style metric: count all direct hits to wp-login.php (GET+POST), excluding referers.
    login_hits = [r for r in rows if r['path'].startswith('/wp-login.php') and r['method'] in ('GET', 'POST')]
    if login_hits:
        print('\nwp-login direct hits (GET+POST):')
        print(f'- total: {len(login_hits)}')
        by_ip = Counter((r['ip'], r['method']) for r in login_hits)
        for (ip, method), n in by_ip.most_common():
            print(f'- {ip} {method}: {n}')

    # Distill easy-quotes version from requests
    vers = Counter()
    for r in rows:
        m = re.search(r'/wp-content/plugins/easy-quotes/[^?]+\?ver=([^&\s]+)', r['path'])
        if m:
            vers[m.group(1)] += 1
    if vers:
        print('\neasy-quotes versions seen:')
        for v, n in vers.most_common(10):
            print(f'- {v}: {n}')

    email = extract_sqlmap_blind_string(rows, 'user_email')
    if email:
        print(f'\nsqlmap exfiltrated user_email: {email}')

    pw = extract_sqlmap_blind_string(rows, 'user_pass')
    if pw:
        print(f'sqlmap exfiltrated user_pass: {pw}')


if __name__ == '__main__':
    main()

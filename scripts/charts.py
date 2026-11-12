"""Security-console styled SVG charts from results/eval_*.json."""
import json, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
T = json.load(open(ROOT / "results/eval_test.json")); D = json.load(open(ROOT / "results/eval_dev.json")); A = json.load(open(ROOT / "results/eval_all.json"))
BG, PANEL, GRID, INK, DIM, RED, AMB, GRN, CYA = "#07070a", "#111116", "#26262e", "#f4f4f6", "#8a8a96", "#ff3b3b", "#ffb020", "#2ee6a6", "#4cc9f0"
F = 'font-family="JetBrains Mono, DejaVu Sans Mono, Consolas, monospace"'


def frame(w, h, title, sub):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
<rect width="{w}" height="{h}" rx="12" fill="{BG}"/><rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="12" fill="none" stroke="{GRID}"/>
<text x="28" y="40" {F} font-size="18" font-weight="700" fill="{INK}">{title}</text><text x="28" y="62" {F} font-size="12" fill="{DIM}">{sub}</text>'''


def save(n, s):
    (ROOT / "results" / n).write_text(s + "</svg>")


# 1. confusion matrix (held-out)
i = T["injection"]; w, h = 760, 430
s = frame(w, h, "Held-out test half: 48 prompts the rules never saw", "rows: truth · columns: verdict at risk ≥ 0.6")
cells = [("attack", "blocked", i["tp"], GRN), ("attack", "allowed", i["fn"], RED), ("benign", "blocked", i["fp"], RED), ("benign", "allowed", i["tn"], GRN)]
for k, (tr, vd, n, c) in enumerate(cells):
    x = 200 + (k % 2) * 260; y = 110 + (k // 2) * 140
    s += f'<rect x="{x}" y="{y}" width="240" height="120" rx="10" fill="{c}" fill-opacity="{0.16 if n else 0.05}" stroke="{c}" stroke-opacity="0.7"/>'
    s += f'<text x="{x + 120}" y="{y + 70}" {F} font-size="46" font-weight="800" fill="{c}" text-anchor="middle">{n}</text>'
for k, lab in enumerate(["BLOCKED", "ALLOWED"]):
    s += f'<text x="{320 + k * 260}" y="100" {F} font-size="13" fill="{DIM}" text-anchor="middle" letter-spacing="3">{lab}</text>'
for k, lab in enumerate(["ATTACK", "BENIGN"]):
    s += f'<text x="186" y="{176 + k * 140}" {F} font-size="13" fill="{DIM}" text-anchor="end" letter-spacing="3">{lab}</text>'
rec = i["tp"] / (i["tp"] + i["fn"]); s += f'<text x="28" y="{h - 22}" {F} font-size="14" fill="{INK}">recall {100 * rec:.0f}% · false alarms {i["fp"]} of {i["fp"] + i["tn"]} benign · precision {100 * i["tp"] / max(1, i["tp"] + i["fp"]):.0f}%</text>'
save("confusion.svg", s)

# 2. recall by category, dev vs test
cats = [c for c in A["injection"]["by_category"] if c != "BENIGN"]
w, h = 900, 110 + 44 * len(cats); x0, x1 = 210, 840
s = frame(w, h, "Attacks blocked, by technique", "development half (rules written from it) vs held-out test half")
for g in range(0, 101, 25):
    gx = x0 + (x1 - x0) * g / 100; s += f'<line x1="{gx}" y1="84" x2="{gx}" y2="{h - 20}" stroke="{GRID}"/><text x="{gx}" y="{h - 6}" {F} font-size="11" fill="{DIM}" text-anchor="middle">{g}%</text>'
for k, c in enumerate(sorted(cats)):
    y = 96 + k * 44
    s += f'<text x="{x0 - 12}" y="{y + 18}" {F} font-size="13" fill="{INK}" text-anchor="end">{c.lower().replace("_", " ")}</text>'
    for j, (src, col) in enumerate([(D, DIM), (T, RED)]):
        bc = src["injection"]["by_category"].get(c)
        if not bc: continue
        v = bc["flagged"] / bc["n"]; bw = (x1 - x0) * v
        s += f'<rect x="{x0}" y="{y + j * 15}" width="{max(bw, 2)}" height="12" rx="3" fill="{col}"><animate attributeName="width" from="0" to="{max(bw, 2)}" dur="1s" fill="freeze"/></rect>'
        s += f'<text x="{x0 + max(bw, 2) + 6}" y="{y + j * 15 + 10}" {F} font-size="10" fill="{col}">{bc["flagged"]}/{bc["n"]}</text>'
s += f'<rect x="{w - 260}" y="30" width="12" height="12" fill="{DIM}"/><text x="{w - 242}" y="40" {F} font-size="12" fill="{INK}">dev</text><rect x="{w - 190}" y="30" width="12" height="12" fill="{RED}"/><text x="{w - 172}" y="40" {F} font-size="12" fill="{INK}">held-out test</text>'
save("by_category.svg", s)

# 3. threshold sweep (all 100 prompts)
sw = A["injection"]["sweep"]; w, h = 760, 470; x0, x1, y0, y1 = 90, 720, 400, 90
sx = lambda v: x0 + (x1 - x0) * v; sy = lambda v: y0 - (y0 - y1) * v
s = frame(w, h, "Choosing the threshold", "all 100 prompts · each dot is one threshold from 0.0 to 1.0")
for g in [0, .25, .5, .75, 1]:
    s += f'<line x1="{sx(g)}" y1="{y1}" x2="{sx(g)}" y2="{y0}" stroke="{GRID}"/><line x1="{x0}" y1="{sy(g)}" x2="{x1}" y2="{sy(g)}" stroke="{GRID}"/>'
    s += f'<text x="{sx(g)}" y="{y0 + 20}" {F} font-size="11" fill="{DIM}" text-anchor="middle">{int(g * 100)}%</text><text x="{x0 - 10}" y="{sy(g) + 4}" {F} font-size="11" fill="{DIM}" text-anchor="end">{int(g * 100)}%</text>'
s += f'<text x="{(x0 + x1) / 2}" y="{y0 + 44}" {F} font-size="12" fill="{INK}" text-anchor="middle">benign prompts blocked (false-positive rate)</text>'
s += f'<text x="24" y="{(y0 + y1) / 2}" {F} font-size="12" fill="{INK}" transform="rotate(-90 24 {(y0 + y1) / 2})" text-anchor="middle">attacks blocked (recall)</text>'
pts = " ".join(f"{sx(p['false_positive_rate']):.1f},{sy(p['recall']):.1f}" for p in sorted(sw, key=lambda p: (p["false_positive_rate"], p["recall"])))
s += f'<polyline points="{pts}" fill="none" stroke="{CYA}" stroke-width="2.5"/>'
for p in sw:
    c = RED if abs(p["threshold"] - 0.6) < 1e-9 else CYA
    s += f'<circle cx="{sx(p["false_positive_rate"])}" cy="{sy(p["recall"])}" r="{7 if c == RED else 4}" fill="{c}"/>'
d = next(p for p in sw if abs(p["threshold"] - 0.6) < 1e-9)
s += f'<text x="{sx(d["false_positive_rate"]) + 14}" y="{sy(d["recall"]) + 22}" {F} font-size="13" fill="{RED}">default 0.6: {100 * d["recall"]:.0f}% blocked, {100 * d["false_positive_rate"]:.0f}% false alarms</text>'
save("threshold_sweep.svg", s)

# 4. PII tiles (held-out seed)
P = T["pii"]; w, h = 900, 300
s = frame(w, h, "Personal data found and masked", f"{sum(v['tp'] + v['fn'] for v in P.values())} synthetic values in sentences + {T['pii_negatives']['n']} look-alikes that must be left alone (seed 7)")
for k, (cat, v) in enumerate(P.items()):
    x = 28 + k * 142; y = 90
    prec = v["tp"] / max(1, v["tp"] + v["fp"]); recl = v["tp"] / max(1, v["tp"] + v["fn"])
    s += f'<rect x="{x}" y="{y}" width="130" height="150" rx="10" fill="{PANEL}" stroke="{GRN}" stroke-opacity="0.6"/>'
    s += f'<text x="{x + 65}" y="{y + 28}" {F} font-size="12" fill="{DIM}" text-anchor="middle">{cat.replace("_", " ").lower()}</text>'
    s += f'<text x="{x + 65}" y="{y + 72}" {F} font-size="30" font-weight="800" fill="{GRN}" text-anchor="middle">{v["tp"]}</text>'
    s += f'<text x="{x + 65}" y="{y + 102}" {F} font-size="11" fill="{INK}" text-anchor="middle">recall {100 * recl:.0f}%</text><text x="{x + 65}" y="{y + 122}" {F} font-size="11" fill="{INK}" text-anchor="middle">precision {100 * prec:.0f}%</text>'
s += f'<text x="28" y="{h - 22}" {F} font-size="13" fill="{AMB}">look-alikes wrongly masked: {T["pii_negatives"]["false_alarms"]} of {T["pii_negatives"]["n"]} (order numbers, dates, prices, ISBNs, broken IBANs, ticket numbers)</text>'
save("pii.svg", s)
print("ok")

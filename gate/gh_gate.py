"""GitHub Actions の上のゲート(段階 1)。証拠を読み、フローを最初から再生して、公開を許すかを判定する。

GitHub の利用者は 1 人しかいないため、役割を持つ人(作成者・レビュアー・鍵の保有者)は SSH の鍵で見分ける。
レビュー・承認・署名は、releases/<版>/ に置いた署名(ssh-keygen -Y sign)を証拠にする。
公開を頼んだ GitHub の利用者は roles.toml の [github] で、フローの利用者に読み替える。

各操作は、手元の Gitea のゲート(rel.py)と同じく、Python の意味と Cedar の両方が許したときだけ進める。

使い方: gh_gate.py <版> --art <ビルド A の成果物> --rebuild-hash <ビルド B のハッシュ> --actor <GitHub の利用者>
"""
import argparse
import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import cedarpy

import gen_cedar
from flowdef import ROOT, load
from test_agree import cedar_resource, python_allows

STAGE = "stage1"
REPO = ROOT.parent
flow, dom = load(STAGE)
CONF = tomllib.loads((ROOT / "roles.toml").read_text())
ROLES = {u: set(rs) for u, rs in CONF["roles"].items()}


def decide(action, user, r, ctx):
    py = python_allows(flow, dom, action, user, ROLES, r, ctx)
    ents = [{"uid": {"type": "User", "id": u}, "attrs": {}, "parents": [{"type": "Role", "id": x} for x in ROLES[u]]}
            for u in ROLES]
    ents += [{"uid": {"type": "Role", "id": x}, "attrs": {}, "parents": []} for x in list(dom.ROLES) + [dom.AGENT_ROLE]]
    ents.append({"uid": {"type": "Release", "id": r["version"]}, "attrs": cedar_resource(dom, r), "parents": []})
    req = {"principal": f'User::"{user}"', "action": f'Action::"{action}"', "resource": f'Release::"{r["version"]}"',
           "context": ctx}
    ced = cedarpy.is_authorized(req, gen_cedar.generate(STAGE), ents).decision == cedarpy.Decision.Allow
    if py != ced:
        sys.exit(f"判定の不一致: {action} by {user}: Python={py} Cedar={ced}(意味とポリシーがずれている)")
    return py


def step(r, action, user, ctx=None, obs=None):
    ctx = {"in_ceremony": True, **(ctx or {})}
    if user not in ROLES:
        sys.exit(f"拒否: {action} by {user}: roles.toml に無い利用者")
    if not decide(action, user, r, ctx):
        a = flow["_actions"][action]
        why = [f"ガード {g} を満たさない" for g in a.get("guards", []) if not dom.GUARDS[g].py(r, user, ctx)]
        sys.exit(f"拒否: {action} by {user}(状態 {r['state']}): " + (" / ".join(why) or "役割か状態が合わない"))
    a = flow["_actions"][action]
    for e in a.get("effects", []):
        dom.EFFECTS[e].py(r, user, obs or {})
    if a["to"] != "=":
        r["state"] = a["to"]
    print(f"許可: {action} by {user} → {r['state']}")


def verify(ver, action, user, sig):
    """sig が user の鍵で「<版> <操作> <ハッシュ>」に付けた署名かを確かめ、署名した対象のハッシュを返す。"""
    msg = (sig.parent / f"{sig.stem}.msg").read_text().strip()
    m = re.fullmatch(rf"{re.escape(ver)} {action} ([0-9a-f]{{64}})", msg or "")
    if not m:
        sys.exit(f"拒否: {sig.name} の対象の書式が違う")
    v = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(ROOT / "allowed_signers"), "-I", user,
                        "-n", action, "-s", str(sig)], input=msg + "\n", capture_output=True, text=True)
    if v.returncode != 0:
        sys.exit(f"拒否: {sig.name} の署名を {user} の鍵で検証できない: {v.stderr.strip()}")
    return m.group(1)


def evidence(d, action):
    """releases/<版>/<操作>-<利用者>.sig を、ファイル名の順に返す。"""
    return [(p.stem.split("-", 1)[1], p) for p in sorted(d.glob(f"{action}-*.sig"))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ver")
    ap.add_argument("--art", required=True)
    ap.add_argument("--rebuild-hash", required=True)
    ap.add_argument("--actor", required=True)
    a = ap.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", a.ver):
        sys.exit("版の書式が違う")
    d = REPO / "releases" / a.ver
    cand = tomllib.loads((d / "candidate.toml").read_text())
    r = {"version": a.ver, "state": flow["initial"], "author": cand["author"]}
    for var, (_t, py, _c) in dom.VARS.items():
        r[var] = list(py) if isinstance(py, list) else py
    r["emergency"] = bool(cand.get("emergency", False))
    art = hashlib.sha256(Path(a.art).read_bytes()).hexdigest()
    print(f"成果物 {a.ver}: {art}(作成者 {r['author']})")

    step(r, "build", CONF["services"]["ci"], obs={"hash": art})
    step(r, "rebuild", CONF["services"]["rebuilder"],
         obs={"repro": "match" if a.rebuild_hash == art else "mismatch", "rebuild_hash": a.rebuild_hash})
    if r["emergency"]:
        (user, sig), = evidence(d, "emergency_sign") or [(None, None)]
        if sig is None:
            sys.exit("拒否: 緊急の署名の証拠が無い")
        step(r, "emergency_sign", user, obs={"signed_hash": verify(a.ver, "emergency_sign", user, sig)})
    else:
        # レビューと承認は、いまの成果物に対するものだけを数える(別の成果物への承認は使い回せない)
        for action in ("review", "approve_sign"):
            for user, sig in evidence(d, action):
                if verify(a.ver, action, user, sig) != art:
                    sys.exit(f"拒否: {sig.name} は別の成果物に対するもの")
                step(r, action, user)
        sigs = evidence(d, "sign")
        if len(sigs) != 1:
            sys.exit(f"拒否: 署名の証拠が {len(sigs)} 件(1 件だけ要る)")
        user, sig = sigs[0]
        step(r, "sign", user, obs={"signed_hash": verify(a.ver, "sign", user, sig)})
    rm = CONF["github"].get(a.actor)
    if rm is None:
        sys.exit(f"拒否: publish: GitHub の利用者 {a.actor} は roles.toml の [github] に無い")
    step(r, "publish", rm)
    print("ゲート: 公開を許す")


if __name__ == "__main__":
    main()

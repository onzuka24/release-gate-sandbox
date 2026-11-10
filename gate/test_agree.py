"""Python の意味(ゲートが使う判定)と、Cedar の判定(cedarpy)が一致するかを、ランダムな要求で確かめる。

使い方: test_agree.py <段階> [--n 件数] [--mut <mutation> ...]
"""
import argparse
import random
import sys

import cedarpy

import gen_cedar
from flowdef import load

HASHES = ["none", "H1", "H2"]
REPRO = ["none", "match", "mismatch"]


def python_allows(flow, dom, action, user, roles_of, r, ctx):
    a = flow["_actions"].get(action)
    if a is None or a["actor"] == "env":
        return False
    if a["actor"] not in roles_of[user]:
        return False
    if dom.AGENT_ROLE in roles_of[user] and action in dom.AGENT_FORBIDDEN:
        return False
    if r["state"] not in a["from"]:
        return False
    return all(dom.GUARDS[g].py(r, user, ctx) for g in a.get("guards", []))


def cedar_resource(dom, r):
    attrs = {"state": r["state"], "author": {"__entity": {"type": "User", "id": r["author"]}},
             "approval_count": len(r["approvals"]), "max_rounds": r.get("max_rounds", 0)}
    for var in dom.VARS:
        name = dom.CEDAR_ATTR.get(var, var)
        v = r[var]
        attrs[name] = [{"__entity": {"type": "User", "id": u}} for u in v] if var == "approvals" else v
    return attrs


def random_case(flow, dom, users, rnd):
    r = {"state": rnd.choice(flow["states"]), "author": rnd.choice(users)}
    for var, (_t, _p, ctype) in dom.VARS.items():
        if var == "approvals":
            r[var] = rnd.sample(users, rnd.randint(0, 3))
        elif var == "repro":
            r[var] = rnd.choice(REPRO)
        elif ctype == "Long":
            r[var] = rnd.randint(0, 2)
        elif ctype == "Bool":
            r[var] = rnd.random() < 0.5
        else:
            r[var] = rnd.choice(HASHES)
    r["max_rounds"] = flow.get("params", {}).get("max_rounds", 0)
    return r


def run(stage, n=5000, mutations=(), seed=1):
    flow, dom = load(stage, [m for m in mutations if not m.startswith("gen_")])
    policies = gen_cedar.generate(stage, mutations)
    rnd = random.Random(seed)
    roles = list(dom.ROLES) + [dom.AGENT_ROLE]
    # 利用者: 役割ごとに 1 人、役割 ＋ エージェントで 1 人、役割なしで 1 人
    # (ランダムに割り当てると、ある役割を持つ人がいない回が出て、その役割の穴が見えなくなる)
    roles_of = {}
    for x in dom.ROLES:
        roles_of[f"{x}"] = {x}
        roles_of[f"{x}+agent"] = {x, dom.AGENT_ROLE}
    roles_of["nobody"] = set()
    users = list(roles_of)
    actions = [a["name"] for a in flow["actions"]]
    mismatches = allows = 0
    first = None
    for i in range(n):
        r = random_case(flow, dom, users, rnd)
        user, action = rnd.choice(users), rnd.choice(actions)
        ctx = {k: rnd.random() < 0.5 for k in dom.CONTEXT}
        ents = [{"uid": {"type": "User", "id": u}, "attrs": {},
                 "parents": [{"type": "Role", "id": x} for x in roles_of[u]]} for u in users]
        ents += [{"uid": {"type": "Role", "id": x}, "attrs": {}, "parents": []} for x in roles]
        ents.append({"uid": {"type": "Release", "id": "v"}, "attrs": cedar_resource(dom, r), "parents": []})
        req = {"principal": f'User::"{user}"', "action": f'Action::"{action}"', "resource": 'Release::"v"',
               "context": ctx}
        res = cedarpy.is_authorized(req, policies, ents)
        c = res.decision == cedarpy.Decision.Allow
        p = python_allows(flow, dom, action, user, roles_of, r, ctx)
        allows += c
        if c != p:
            mismatches += 1
            first = first or (action, user, sorted(roles_of[user]), r, ctx, c, p)
    return n, mismatches, first, allows


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("stage")
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--mut", action="append", default=[])
    a = ap.parse_args()
    n, mm, first, allows = run(a.stage, a.n, a.mut)
    print(f"  {n} 件の要求(Cedar が許したもの {allows} 件)で、不一致 {mm} 件")
    if first:
        print(f"  最初の不一致: 操作={first[0]} 利用者={first[1]} 役割={first[2]} Cedar={first[5]} Python={first[6]}\n    版={first[3]} 文脈={first[4]}")
    sys.exit(1 if mm else 0)

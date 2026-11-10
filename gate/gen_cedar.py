"""定義 → Cedar のポリシー。

操作ごとに permit を 1 つ作る(役割・元の状態・ガード)。AI エージェントには forbid を重ねる。
環境の操作(actor = "env")にはポリシーを作らない(誰にも許さない)。

使い方: gen_cedar.py <段階> [--mut <mutation> ...]
  生成器の不具合を植える mutation: gen_no_parens(ガードを括弧で囲まない)/ gen_no_agent_forbid(forbid を作らない)
"""
import argparse

from flowdef import ROOT, load


def generate(stage, mutations=()):
    gen_muts = {m for m in mutations if m.startswith("gen_")}
    flow, dom = load(stage, [m for m in mutations if not m.startswith("gen_")])
    out = []
    for a in flow["actions"]:
        if a["actor"] == "env":
            continue
        states = ", ".join(f'"{s}"' for s in a["from"])
        conds = [f"[{states}].contains(resource.state)"]
        for g in a.get("guards", []):
            expr = dom.GUARDS[g].cedar
            conds.append(expr if "gen_no_parens" in gen_muts else f"({expr})")
        out.append(f'// {a["name"]}\npermit(principal in Role::"{a["actor"]}", action == Action::"{a["name"]}", resource)\n'
                   f"when {{ {' && '.join(conds)} }};")
    if "gen_no_agent_forbid" not in gen_muts:
        acts = ", ".join(f'Action::"{x}"' for x in dom.AGENT_FORBIDDEN if x in flow["_actions"])
        out.append(f'// agent_guard: AI エージェントはどの役割に入れられても、これらの操作ができない\n'
                   f'forbid(principal in Role::"{dom.AGENT_ROLE}", action in [{acts}], resource);')
    text = "\n\n".join(out) + "\n"
    path = ROOT / "build" / stage / "policy.cedar"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return text


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("stage")
    ap.add_argument("--mut", action="append", default=[])
    a = ap.parse_args()
    print(generate(a.stage, a.mut))

"""flow/<段階>.toml と domain/<名前>.py を読み、わざと壊す変更(mutation)を当てる。"""
import copy
import importlib
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent


def load(stage, mutations=()):
    flow = tomllib.loads((ROOT / "flow" / f"{stage}.toml").read_text())
    dom = importlib.import_module(f"domain.{flow['domain']}")
    flow = copy.deepcopy(flow)
    for m in mutations:
        apply_mutation(flow, m)
    flow["_actions"] = {a["name"]: a for a in flow["actions"]}
    return flow, dom


def apply_mutation(flow, m):
    """m の書式: drop_guard:<操作>:<ガード> / drop_action:<操作> / drop_effect:<操作>:<効果>"""
    kind, *args = m.split(":")
    acts = {a["name"]: a for a in flow["actions"]}
    if kind == "drop_guard":
        acts[args[0]]["guards"].remove(args[1])
    elif kind == "drop_action":
        flow["actions"] = [a for a in flow["actions"] if a["name"] != args[0]]
    elif kind == "drop_effect":
        acts[args[0]]["effects"].remove(args[1])
    elif kind == "swap_effect":                 # swap_effect:<操作>:<効果>:<差し替える効果>
        e = acts[args[0]]["effects"]
        e[e.index(args[1])] = args[2]
    elif kind == "set_from":                    # set_from:<操作>:<状態>,<状態>
        acts[args[0]]["from"] = args[1].split(",")
    elif kind == "derive":                      # 版をまたぐ文脈の計算の穴(mutate.py が差し替える)。定義は変えない
        pass
    else:
        raise ValueError(f"unknown mutation {m}")

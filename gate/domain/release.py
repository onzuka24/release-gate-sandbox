"""リリースのドメインの意味。flow/*.toml に名前だけ書いたガード・効果・性質を、ここで 3 通りに定義する。

- tla:    TLA+ の式。版は v、操作する人は p。変数は版ごとの関数(art[v] など)
- cedar:  Cedar の式。principal・resource(版)・context で書く
- py:     Python の関数。ゲートが実際の判定に使う。r は版の記録(dict)、p は利用者の名前、ctx は要求の文脈

人が読むのはこのファイルと flow/*.toml。生成器(gen_*.py)と翻訳器(cedar_smt.py)は読まなくてよいことを目指す。
"""
from dataclasses import dataclass, field
from typing import Callable

import z3


# ---- 役割と人(TLA+ のモデルで使う顔ぶれ。ゲートの利用者は lab の設定で別に決める) ----

AUTHOR = "a"                    # 既定の作成者。レビューと鍵の保有者も兼ねる(自己承認が起こりうる配置)
                                # 版ごとの作成者は flow の [params] authors で変えられる(段階 2: 鍵の保有者が別の版の作成者になる)
ROLES = {
    "ci": {"ci"},
    "rebuilder": {"rb"},
    "reviewer": {"a", "r1"},
    "keyholder": {"a", "k1", "k2"},
    "release_manager": {"rm"},
    "security": {"sec"},
}
AGENT_ROLE = "agent"            # AI エージェント。どの役割に入れられても、下の AGENT_FORBIDDEN はできない
AGENT_FORBIDDEN = ["review", "approve_sign", "sign", "emergency_sign", "publish", "post_audit", "revoke",
                   "request_changes", "withdraw", "invalidate_signature", "invalidate_fast_signature",
                   "withdraw_vulnerable"]


# ---- 版の記録(状態以外の変数) ----
# name: (TLA+ の初期値, Python の初期値, Cedar の型)

VARS = {
    "art":       ('"none"', "none", "String"),   # 置かれている成果物のハッシュ(good / evil)
    "built":     ('"none"', "none", "String"),   # ビルド A が記録したハッシュ
    "repro":     ('"none"', "none", "String"),   # 再現ビルドの結果(none / match / mismatch)
    "reviewed":  ("FALSE", False, "Bool"),
    "approvals": ("{}", [], "Set"),              # 署名を承認した人
    "signed":    ('"none"', "none", "String"),   # 署名したもののハッシュ
    "fast":      ("FALSE", False, "Bool"),       # 緊急の道を通った
    "audited":   ("FALSE", False, "Bool"),       # 事後監査が済んだ
    "vuln":      ("FALSE", False, "Bool"),       # 脆弱性が見つかった
    "emergency": ("BOOLEAN", False, "Bool"),     # 緊急の印(TLA+ ではどちらもありうる)
    "rounds":    ("0", 0, "Long"),               # 差し戻しの回数(段階 2)
    "signer":    ('"none"', "none", "String"),   # 署名した鍵の保有者(段階 3)
    # 一度でも公開されたか(段階 3 の反例で足した。署名の無効化で公開済みでなくなっても、ダウングレードの判定には効かせる)
    "was_published": ("FALSE", False, "Bool"),
}
# 版をまたぐ変数(TLA+ だけ。版ごとの関数ではない)
GLOBALS = {
    "pub_order": "<<>>",                         # 公開した版の順(段階 2: ダウングレードの検査に使う)
    "compromised": "{}",                         # 漏洩した鍵の保有者(段階 3)
}
# 要求の文脈(Cedar の context)。版をまたぐ情報は、ゲートが計算して文脈で渡す
CONTEXT = {"in_ceremony": "Bool", "newer_published": "Bool", "my_key_leaked": "Bool", "signer_key_leaked": "Bool"}


def derive_context(records, v, user=None, leaked=()):
    """版をまたぐ文脈を、全部の版の記録と漏洩した鍵の一覧から計算する(ゲートと単体テストが使う)。
    TLA+ ではガードの式そのものを持つので、この関数は TLA+ には現れない。"""
    rank = {w: i for i, w in enumerate(sorted(records))}
    return {"newer_published": any(rank[w] > rank[v] and records[w].get("was_published", False) for w in records),
            "my_key_leaked": user in leaked,
            "signer_key_leaked": records[v].get("signer", "none") in leaked}
# Cedar での属性名(TLA+ の変数名と違うもの)
CEDAR_ATTR = {"art": "art_hash", "built": "build_hash", "signed": "signed_hash", "approvals": "approvers"}


@dataclass
class Guard:
    tla: str
    cedar: str
    py: Callable


@dataclass
class Effect:
    tla: dict                     # 変数 → 次の値の式。"\\in 集合" で非決定
    py: Callable                  # (r, p, obs) → None。obs は実物から読んだ値
    reads_obs: list = field(default_factory=list)


GUARDS = {
    "not_yet_rebuilt": Guard('repro[v] = "none"', 'resource.repro == "none"',
                             lambda r, p, c: r["repro"] == "none"),
    "art_intact": Guard("art[v] = built[v]", "resource.art_hash == resource.build_hash",
                        lambda r, p, c: r["art"] == r["built"]),
    "not_author": Guard("p # AuthorOf[v]", "principal != resource.author",
                        lambda r, p, c: p != r["author"]),
    "repro_match": Guard('repro[v] = "match"', 'resource.repro == "match"',
                         lambda r, p, c: r["repro"] == "match"),
    "not_yet_approved_by_me": Guard("p \\notin approvals[v]", "!(resource.approvers.contains(principal))",
                                    lambda r, p, c: p not in r["approvals"]),
    "two_approvals": Guard("Cardinality(approvals[v]) >= 2", "resource.approval_count >= 2",
                           lambda r, p, c: len(r["approvals"]) >= 2),
    # 儀式の時間は要求の文脈。TLA+ のモデルでは時間を扱わず、いつでも儀式の時間内とみなす
    "in_ceremony": Guard("TRUE", "context.in_ceremony",
                         lambda r, p, c: bool(c.get("in_ceremony"))),
    "emergency_label": Guard("emergency[v]", "resource.emergency",
                             lambda r, p, c: r["emergency"]),
    "sig_matches_build": Guard("signed[v] = built[v] /\\ art[v] = built[v]",
                               "resource.signed_hash == resource.build_hash && resource.art_hash == resource.build_hash",
                               lambda r, p, c: r["signed"] == r["built"] and r["art"] == r["built"]),
    # 最上位に「または」を持つガード(process_b で生成器の括弧の不具合が出た形)
    "checked_or_fast": Guard('(repro[v] = "match" /\\ reviewed[v]) \\/ fast[v]',
                             'resource.repro == "match" && resource.reviewed || resource.fast',
                             lambda r, p, c: (r["repro"] == "match" and r["reviewed"]) or r["fast"]),
    "integrity_broken": Guard('art[v] # built[v] \\/ repro[v] = "mismatch"',
                              'resource.art_hash != resource.build_hash || resource.repro == "mismatch"',
                              lambda r, p, c: r["art"] != r["built"] or r["repro"] == "mismatch"),
    "audit_pending": Guard("fast[v] /\\ ~audited[v]", "resource.fast && !resource.audited",
                           lambda r, p, c: r["fast"] and not r["audited"]),
    "no_vuln_yet": Guard("~vuln[v]", "!resource.vuln", lambda r, p, c: not r["vuln"]),
    "vuln_found": Guard("vuln[v]", "resource.vuln", lambda r, p, c: r["vuln"]),
    # ---- 段階 2 ----
    "rounds_left": Guard("rounds[v] < MaxRounds", "resource.rounds < resource.max_rounds",
                         lambda r, p, c: r["rounds"] < r["max_rounds"]),
    # 新しい版が一度でも公開されたなら、古い版は公開できない(ダウングレードの防止)
    # 段階 2 では「いまの状態が公開済みか失効」で判定していた。段階 3 の反例(新しい版の署名を無効にすると古い版が公開できる)で直した
    "not_superseded": Guard("~\\E w \\in Releases: Rank[w] > Rank[v] /\\ was_published[w]",
                            "!context.newer_published", lambda r, p, c: not c["newer_published"]),
    "superseded": Guard("\\E w \\in Releases: Rank[w] > Rank[v] /\\ was_published[w]",
                        "context.newer_published", lambda r, p, c: c["newer_published"]),
    # ---- 段階 3 ----
    "key_not_leaked": Guard("p \\notin compromised", "!context.my_key_leaked", lambda r, p, c: not c["my_key_leaked"]),
    "signer_key_valid": Guard("signer[v] \\notin compromised", "!context.signer_key_leaked",
                              lambda r, p, c: not c["signer_key_leaked"]),
    "signed_by_leaked": Guard("signer[v] \\in compromised", "context.signer_key_leaked",
                              lambda r, p, c: c["signer_key_leaked"]),
    "not_fast": Guard("~fast[v]", "!resource.fast", lambda r, p, c: not r["fast"]),
    "is_fast": Guard("fast[v]", "resource.fast", lambda r, p, c: r["fast"]),
    # 環境の操作(鍵の漏洩)のガード。Cedar には出ない
    "can_leak": Guard("p \\notin compromised /\\ Cardinality(compromised) < MaxLeaks", "false",
                      lambda r, p, c: False),
}


def _set(k, v):
    def f(r, p, obs):
        r[k] = v
    return f


def _obs(k, src):
    def f(r, p, obs):
        r[k] = obs[src]
    return f


EFFECTS = {
    # ハッシュは TLA+ では good / evil の 2 値、実物では本物のハッシュ
    "record_build": Effect({"art": '"good"', "built": '"good"'},
                           lambda r, p, o: r.update(art=o["hash"], built=o["hash"]), ["hash"]),
    # 再現ビルド: すり替えがなくても、ビルド環境のずれ(drift)で一致しないことがある(process_b の試験環境の発見)
    "compare_build": Effect({"repro": '\\in IF art[v] = built[v] THEN {"match", "mismatch"} ELSE {"mismatch"}'},
                            _obs("repro", "repro"), ["repro"]),
    "swap_artifact": Effect({"art": '"evil"'}, _obs("art", "hash"), ["hash"]),
    "mark_reviewed": Effect({"reviewed": "TRUE"}, _set("reviewed", True)),
    "add_approval": Effect({"approvals": "approvals[v] \\cup {p}"},
                           lambda r, p, o: r["approvals"].append(p)),
    "sign_artifact": Effect({"signed": "art[v]", "signer": "p"},
                            lambda r, p, o: r.update(signed=o["signed_hash"], signer=p), ["signed_hash"]),
    "mark_fast": Effect({"fast": "TRUE"}, _set("fast", True)),
    "done_audit": Effect({"audited": "TRUE"}, _set("audited", True)),
    "raise_vuln": Effect({"vuln": "TRUE"}, _set("vuln", True)),
    # ---- 段階 2 ----
    "bump_round": Effect({"rounds": "rounds[v] + 1"}, lambda r, p, o: r.update(rounds=r["rounds"] + 1)),
    # 差し戻し: ビルドからやり直す。承認は別の効果に分けてある(残してしまう穴を植えられるように)
    "reset_build": Effect({"art": '"none"', "built": '"none"', "repro": '"none"', "reviewed": "FALSE"},
                          lambda r, p, o: r.update(art="none", built="none", repro="none", reviewed=False)),
    "reset_approvals": Effect({"approvals": "{}"}, lambda r, p, o: r.update(approvals=[])),
    "record_publish": Effect({"pub_order": "Append(pub_order, v)", "was_published": "TRUE"},
                             lambda r, p, o: r.update(was_published=True)),
    # ---- 段階 3 ----
    "leak_key": Effect({"compromised": "compromised \\cup {p}"}, lambda r, p, o: None),
    "clear_signature": Effect({"signed": '"none"', "signer": '"none"'},
                              lambda r, p, o: r.update(signed="none", signer="none")),
}


# ---- 設計の性質(TLA+) ----

PROPERTIES = {
    # 公開されたものは、署名したものと同じで、ビルド A の記録とも同じ
    "PublishedIsAuthentic": '\\A v \\in Releases: st[v] = "published" => (signed[v] = built[v] /\\ art[v] = built[v])',
    # 署名鍵は、すり替えられたものに一度も署名しない
    "SignedIsAuthentic": '\\A v \\in Releases: signed[v] \\in {"none", built[v]}',
    # 公開されたものは、再現ビルドが一致しレビュー済みか、緊急の道を通ったもの
    "PublishedIsChecked": '\\A v \\in Releases: st[v] = "published" => ((repro[v] = "match" /\\ reviewed[v]) \\/ fast[v])',
    # 署名には 2 人の承認が要る(緊急の道を除く)
    "TwoPersonSigning": '\\A v \\in Releases: (signed[v] # "none" /\\ ~fast[v]) => Cardinality(approvals[v]) >= 2',
    # 作成者は自分の変更の署名を承認できない
    "NoSelfApproval": "\\A v \\in Releases: AuthorOf[v] \\notin approvals[v]",
    # ---- 段階 2 ----
    # 差し戻しの回数は上限を超えない
    "RoundsBounded": "\\A v \\in Releases: rounds[v] <= MaxRounds",
    # 署名の承認は、いまのビルドのレビューの後にだけある(差し戻しで古い承認が残らない)
    "ApprovalsAfterReview": "\\A v \\in Releases: approvals[v] # {} => reviewed[v]",
    # 公開は版の順にだけ進む(新しい版の後に古い版を公開しない)
    # 同じ版の公開し直し(段階 3 の署名のやり直し)は許す。段階 2 で「<」と書いていたのを、段階 3 の反例で「<=」に直した
    "NoDowngrade": "\\A i, j \\in 1..Len(pub_order): i < j => Rank[pub_order[i]] <= Rank[pub_order[j]]",
    # ---- 段階 3 ----
    # 署名済み・公開済みの版に漏洩した鍵の署名があれば、いつか必ず差し替わる(公開済みの版も含めて、すべての版で)
    # 却下・失効した版は対象外(最初はすべての版を対象に書き、却下された版で反例が出たので絞った)
    "LeakedSignaturesReplaced": ('\\A v \\in Releases: (signer[v] \\in compromised /\\ st[v] \\in {"signed", "published"})'
                                 ' ~> (signer[v] \\notin compromised \\/ st[v] \\in {"rejected", "revoked"})'),
    # 漏洩した鍵で署名された版を、公開する操作は起きない
    "NoPublishWithLeakedKey": ('[][\\A v \\in Releases: (st[v] # "published" /\\ st\'[v] = "published")'
                               " => signer[v] \\notin compromised]_vars"),
    # いつか終わる / 緊急の署名にはいつか事後監査 / 脆弱性が見つかればいつか失効
    "EventuallyDone": "\\A v \\in Releases: <>(st[v] \\in Terminal)",
    "FastPathAudited": "\\A v \\in Releases: fast[v] ~> audited[v]",
    "VulnRevoked": '\\A v \\in Releases: vuln[v] ~> (st[v] = "revoked")',
    # 段階 3: 脆弱性が見つかった版は、いつか配布されなくなる(失効か却下)。署名の無効化で公開済みから外れ、却下される道があるため
    "VulnWithdrawn": '\\A v \\in Releases: vuln[v] ~> (st[v] \\in {"revoked", "rejected"})',
    # 段階 3: 既知の脆弱性がある版を、公開する操作は起きない(署名をやり直した版の公開し直しで起こりうる)
    "NoPublishKnownVulnerable": ('[][\\A v \\in Releases: (st[v] # "published" /\\ st\'[v] = "published")'
                                 " => ~vuln[v]]_vars"),
}


# ---- 権限の性質(SMT)。q は記号の要求(cedar_smt.py の Req)。q.ok(操作) は「Cedar が許す」 ----

def smt_properties(q, flow):
    r, P = q.res, q.principal
    stage2 = {}
    if flow["name"].startswith("Stage3"):
        stage2.update({
            "SignNotWithLeakedKey": z3.Implies(z3.Or(q.ok("sign"), q.ok("emergency_sign")), z3.Not(q.ctx.my_key_leaked)),
            "PublishNotLeakedSignature": z3.Implies(q.ok("publish"), z3.Not(q.ctx.signer_key_leaked)),
            "InvalidateOnlyLeaked": z3.Implies(q.ok("invalidate_signature"),
                                               z3.And(q.ctx.signer_key_leaked, P.role("security"))),
        })
    if flow["name"] != "Stage1":   # 定義の中身(操作の有無)では決めない。操作を外す穴で性質まで消えるため
        stage2.update({
            "PublishNotDowngrade": z3.Implies(q.ok("publish"), z3.Not(q.ctx.newer_published)),
            "WithdrawOnlySuperseded": z3.Implies(q.ok("withdraw"), q.ctx.newer_published),
            "ChangesNotByAuthor": z3.Implies(q.ok("request_changes"), P.id != r.author),
            "ChangesBounded": z3.Implies(q.ok("request_changes"), r.rounds < r.max_rounds),
        })
    return {
        **stage2,
        # 署名は、承認 2 件・作成者以外・儀式の時間内・成果物が記録と同じ、のときだけ
        "SignNeedsTwoApprovals": z3.Implies(q.ok("sign"), r.approval_count >= 2),
        "SignNotByAuthor": z3.Implies(q.ok("sign"), P.id != r.author),
        "SignOnlyInCeremony": z3.Implies(q.ok("sign"), q.ctx.in_ceremony),
        "SignOnlyIntact": z3.Implies(q.ok("sign"), r.art_hash == r.build_hash),
        "EmergencySignNeedsLabel": z3.Implies(q.ok("emergency_sign"), z3.And(r.emergency, P.id != r.author)),
        # 公開は、リリース担当が、署名済みで記録と一致し、検査済みか緊急の道を通ったものだけ
        "PublishOnlyByReleaseManager": z3.Implies(q.ok("publish"), P.role("release_manager")),
        "PublishOnlySigned": z3.Implies(q.ok("publish"), r.state == z3.StringVal("signed")),
        "PublishOnlyMatching": z3.Implies(q.ok("publish"), z3.And(r.signed_hash == r.build_hash, r.art_hash == r.build_hash)),
        "PublishOnlyChecked": z3.Implies(q.ok("publish"),
                                         z3.Or(z3.And(r.repro == z3.StringVal("match"), r.reviewed), r.fast)),
        # 職務の分離
        "NoSelfReview": z3.Implies(q.ok("review"), P.id != r.author),
        "NoSelfApproval": z3.Implies(q.ok("approve_sign"), P.id != r.author),
        "NoDoubleApproval": z3.Implies(q.ok("approve_sign"), z3.Not(r.approvers_has_principal)),
        "ReviewNeedsRepro": z3.Implies(q.ok("review"), r.repro == z3.StringVal("match")),
        # 失効と事後監査はセキュリティ担当だけ
        "RevokeOnlyBySecurity": z3.Implies(q.ok("revoke"), P.role("security")),
        "AuditOnlyBySecurity": z3.Implies(q.ok("post_audit"), P.role("security")),
        # 環境の操作は誰にも許さない
        "NobodyTampers": z3.Not(q.ok("tamper")),
        "NobodyRaisesVuln": z3.Not(q.ok("find_vuln")),
        # AI エージェントは、どの役割に入れられても、決まった操作ができない
        **{f"AgentCannot_{a}": z3.Implies(P.role(AGENT_ROLE), z3.Not(q.ok(a))) for a in AGENT_FORBIDDEN},
    }

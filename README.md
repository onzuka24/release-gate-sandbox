# release-gate-sandbox

**試験用のリポジトリです。プロトタイプ品質で、本番に転用しません。**
リリースの手続き(レビュー、2 人の承認、署名、公開)のゲートを、GitHub の権限の仕組みに載せられるかを試しています。

## 公開の道

公開は Actions の `publish`(手動で起動)からだけ行えます。

1. ビルド A とビルド B を別のジョブで行う(再現可能なビルド)
2. ゲート(`gate/gh_gate.py`)が `releases/<版>/` の証拠の署名を検証し、フローを最初から再生する。
   各操作は、フローの定義から作った Cedar のポリシーと Python の意味の両方が許したときだけ進む
3. environment `release` の必須のレビュアーが承認すると、タグを作って公開する

`v*` のタグは、ルールセットで誰も作れません。例外は deploy key だけで、その秘密鍵は environment `release` の secret にだけあります。

## 構成

```
app/                   題材のアプリ(西暦を和暦に変換)と、再現可能なビルド
gate/flow/stage1.toml  フローの定義
gate/domain/release.py ガードと効果の意味
gate/gh_gate.py        ゲート
gate/roles.toml        利用者と役割
gate/allowed_signers   役割を持つ人の公開鍵
releases/<版>/         候補と、レビュー・承認・署名の証拠
```

利用者と役割は試験用の架空のものです。

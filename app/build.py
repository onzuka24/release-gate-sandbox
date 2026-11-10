"""再現可能なビルド: wareki/ を .pyz にする。どこでビルドしても、同じソースならバイト単位で同じになる。

ファイルの順序・時刻・権限を固定する。時刻は SOURCE_DATE_EPOCH(既定 2026-01-01)。
SOURCE_DATE_EPOCH が違うと結果も違う(ビルド環境のずれ)。

使い方: python3 build.py <ソースのディレクトリ> <出力 .pyz>  → ハッシュを表示
"""
import hashlib
import os
import sys
import time
import zipfile
from pathlib import Path


def build(src, out):
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1767225600"))
    stamp = time.gmtime(epoch)[:6]
    files = sorted(p for p in Path(src, "wareki").rglob("*.py"))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            info = zipfile.ZipInfo(str(p.relative_to(src)), stamp)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
        main = zipfile.ZipInfo("__main__.py", stamp)
        main.external_attr = 0o644 << 16
        z.writestr(main, b"import runpy\nrunpy.run_module('wareki', run_name='__main__')\n")
    return hashlib.sha256(Path(out).read_bytes()).hexdigest()


if __name__ == "__main__":
    print(build(sys.argv[1], sys.argv[2]))

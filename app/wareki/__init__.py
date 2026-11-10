"""西暦の日付を和暦に変換する(題材のアプリ)。"""
import datetime as _dt

__version__ = "0.2.0"

ERAS = [  # (開始日, 元号)
    (_dt.date(2019, 5, 1), "令和"),
    (_dt.date(1989, 1, 8), "平成"),
    (_dt.date(1926, 12, 25), "昭和"),
]


def parse(text):
    y, m, d = (int(x) for x in text.strip().split("-"))
    return _dt.date(y, m, d)


def to_wareki(text):
    day = parse(text)
    for start, name in ERAS:
        if day >= start:
            n = day.year - start.year + 1
            return f"{name}{'元' if n == 1 else n}年{day.month}月{day.day}日"
    raise ValueError("昭和より前は扱わない")

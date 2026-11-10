import sys

from wareki import to_wareki

for arg in sys.argv[1:]:
    print(to_wareki(arg))

import re, sys
x = open(sys.argv[1], encoding='utf-8').read()
ts = [m.group(1) for m in re.finditer(r'text="([^"]{3,80})"', x)]
print('nodes:', len(ts))
for t in ts[:30]:
    print('-', t)

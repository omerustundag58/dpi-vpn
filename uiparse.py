import re, sys
fn = sys.argv[1] if len(sys.argv) > 1 else 'ui.xml'
x = open(fn, encoding='utf-8').read()
for m in re.finditer(r'<node[^>]*>', x):
    node = m.group(0)
    rid = re.search(r'resource-id="([^"]*)"', node)
    txt = re.search(r'text="([^"]*)"', node)
    b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node)
    if not b:
        continue
    cx = (int(b.group(1)) + int(b.group(3))) // 2
    cy = (int(b.group(2)) + int(b.group(4))) // 2
    t = txt.group(1) if txt else ''
    r = rid.group(1) if rid else ''
    if 'dpivpn' in r or t.strip():
        print(f"{r} | {t[:40]} | {cx},{cy}")

import re

with open("../FW-UV_db.conf", "r") as f:
    conf = f.read()

intent = " " * 4
lines = conf.split('\n')
re_next = re.compile("[ \t]*next.*")
re_edit = re.compile("[ \t]*edit.*")
re_config = re.compile("[ \t]*config.*")
re_end = re.compile("[ \t]*end.*")

output = ''
ic = 0
ie = 0
lc = 0
for line in lines:
    if ic == 0 and ie != 0:
        print(lc, "ERROR: config intent 0 but edit intent", ie)
    lc += 1
    if re_config.match(line) is not None:
        output += intent * (ic + ie) + line + '\n'
        ic += 1
        continue
    elif re_edit.match(line) is not None:
        output += intent * (ic + ie) + line + '\n'
        ie += 1
        continue
    elif re_next.match(line) is not None:
        ie -= 1
        if ie < 0:
            print(lc, "ERROR: next without edit!")
            ie = 0
        output += intent * (ic + ie) + line + '\n'
        continue
    elif re_end.match(line) is not None:
        ic -= 1
        if ic < 0:
            print(lc, "ERROR: end without config!")
            ic = 0
        output += intent * (ic + ie) + line + '\n'
        continue
    else:
        output += intent * (ic + ie) + line + '\n'

with open('/tmp/pretty_FW-UV_db.conf', 'w') as f:
    f.write(output)

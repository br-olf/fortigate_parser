import xml

import xml.etree.ElementTree as ET

tree = ET.parse("pp_IDS_table_html_export_all.xml")
root = tree.getroot()

headers = ["Name", "Severity", "Target", "OS", "Default"]
rows = []
for row in root:
    cols = []
    for col in row:
        cols.append(list(col)[0].text)
    rows.append(cols)

if False:
    with open('IDS_table.csv','w') as f:
        f.write(','.join(headers))
        f.write('\n')
        for row in rows:
            f.write('"'+'","'.join(row)+'"')
            f.write('\n')

rset = set()
for row in rows:
    rset.add(row[0])

print(len(rset),len(rows))
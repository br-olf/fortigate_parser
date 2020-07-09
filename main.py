
from lark import Lark
import logging

logging.basicConfig(level=logging.DEBUG)

with open("fortigate.lark", "r") as f:
    grammar = f.read()

with open("../FW-UV_db.conf", "r") as f:
    conf = f.read()

parser = Lark(grammar,
              parser="lalr",
              propagate_positions=True,
              start="root",
              debug=True)

parsed_conf = parser.parse(conf)
#print(parsed_conf.pretty())

"""Extract config sections"""
for config in parsed_conf.children:
    if config.data == 'config':
        config_branch = config.children[0].children
    elif config.data == 'config_branch':
        config_branch = config.children
    else:
        raise RuntimeError('invalid parse tree')

    if config_branch[0] == 'firewall':
        if config_branch[1] == 'address':
            firewall_address = config.children
        elif config_branch[1] == 'policy':
            firewall_policy = config

import logging
import re

_re_next = re.compile("[ \t]*next.*")
_re_edit = re.compile("[ \t]*edit.*")
_re_config = re.compile("[ \t]*config.*")
_re_end = re.compile("[ \t]*end.*")


def pp_fortigate_conf(conf: str, intent: str = " " * 2) -> str:
    """Intents fortigate configurations to make them more human readable
    :param conf The raw fortigate configuration
    :param intent A string used as base intent"""
    lines = conf.replace('\r', '\n').replace('\n\n', '\n').split('\n')
    output = ''
    conf_intent_count = 0
    edit_intent_count = 0
    line_count = 0
    for line in lines:
        line = line.strip(' \t')
        if conf_intent_count == 0 and edit_intent_count != 0:
            logging.error(
                "line " + str(line_count) + ": config intent is 0 but edit intent is " + str(edit_intent_count))
        line_count += 1
        if _re_config.match(line) is not None:
            output += intent * (conf_intent_count + edit_intent_count) + line + '\n'
            conf_intent_count += 1
            continue
        elif _re_edit.match(line) is not None:
            output += intent * (conf_intent_count + edit_intent_count) + line + '\n'
            edit_intent_count += 1
            continue
        elif _re_next.match(line) is not None:
            edit_intent_count -= 1
            if edit_intent_count < 0:
                logging.error("line " + str(line_count) + ": next without edit!")
                edit_intent_count = 0
            output += intent * (conf_intent_count + edit_intent_count) + line + '\n'
            continue
        elif _re_end.match(line) is not None:
            conf_intent_count -= 1
            if conf_intent_count < 0:
                logging.error("line " + str(line_count) + ": end without config!")
                conf_intent_count = 0
            output += intent * (conf_intent_count + edit_intent_count) + line + '\n'
            continue
        else:
            output += intent * (conf_intent_count + edit_intent_count) + line + '\n'
    return output


if __name__ == '__main__':
    with open("../FW-SV_db.conf", "r") as f:
        fortigate_config = f.read()

    with open("pretty_SV_fortigate.conf", "w") as f:
        f.write(pp_fortigate_conf(fortigate_config))

    with open("../FW-UV_db.conf", "r") as f:
        fortigate_config = f.read()

    with open("pretty_UV_fortigate.conf", "w") as f:
        f.write(pp_fortigate_conf(fortigate_config))


#import re

import wayround_org.mail.miscs

# C2S_COMMAND_LINE_RE = re.compile(
#    r'^(?P<tag>.*?) (?P<command>.*?)( (?P<rest>.*))?$'
#    )


def c2s_command_line_parse(data):

    if not isinstance(data, bytes):
        raise TypeError("`data' type must be bytes")

    if not data.endswith(wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR):
        raise TypeError(
            "`data' must be termenated with `{}'".format(
                wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
                )
            )

    ret = None

    # NOTE: currently all input data assumed to be utf-8 compatible
    data = str(data[:-2], 'utf-8')

    data_splitted = data.split(' ')

    if len(data_splitted) < 2:
        ret = None

    else:

        ret = {
            'tag': data_splitted[0],
            'command': data_splitted[1],
            'rest': data_splitted[2:]
            }

        ret['command'] = ret['command'].upper()

    return ret


def s2c_response_format(tag, code, comment=None):

    if not isinstance(tag, str):
        raise TypeError("`tag' must be str")

    if not isinstance(code, str):
        raise TypeError("`code' must be str")

    if comment is not None and not isinstance(comment, str):
        raise TypeError("`comment' must be str")

    ret = bytes(
        '{} {}'.format(tag, code.upper()),
        'utf-8'
        )

    if comment is not None:
        ret += bytes(' {}'.format(comment), 'utf-8')

    ret += wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

    return ret


def string_param_parse(value):
    ret = ''
    if value.startswith('"') and value.endswith('"'):
        ret = value[1:-1]
    else:
        ret = value
    return ret

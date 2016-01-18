
import wayround_org.mail.miscs


AUTHLESS_COMMANDS = ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT']


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

    if len(data_splitted) < 1:
        ret = None

    else:

        ret = {
            'command': data_splitted[0],
            'rest': data_splitted[1:]
            }

        ret['command'] = ret['command'].upper()

    return ret


def s2c_response_format(code, finishing, text):

    if not isinstance(code, int):
        raise TypeError("`code' must be int")

    if not isinstance(finishing, bool):
        raise TypeError("`finishing' must be bool")

    if text is not None and not isinstance(text, str):
        raise TypeError("`text' must be str")

    ret = b''

    ret += bytes(str(code), 'utf-8')

    if finishing:
        ret += b' '
    else:
        ret += b'-'

    if text is not None:
        ret += bytes(text, 'utf-8')

    ret += wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

    return ret

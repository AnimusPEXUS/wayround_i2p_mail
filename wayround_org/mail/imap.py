
#import re

import wayround_org.utils.types_presets

import wayround_org.mail.miscs


# C2S_COMMAND_LINE_RE = re.compile(
#    r'^(?P<tag>.*?) (?P<command>.*?)( (?P<rest>.*))?$'
#    )

IMAP_SEARCH_KEYS = {
    'ALL': [],
    'ANSWERED': [],
    'BCC': ['string'],
    'BEFORE': ['date'],
    'BODY': ['string'],
    'CC': ['string'],
    'DELETED': [],
    'DRAFT': [],
    'FLAGGED': [],
    'FROM': ['string'],
    'HEADER': ['field-name', 'string'],
    'KEYWORD': ['flag'],
    'LARGER': ['n'],
    'NEW': [],
    'NOT': ['search-key'],
    'OLD': [],
    'ON': ['date'],
    'OR': ['search-key1', 'search-key2'],
    'RECENT': [],
    'SEEN': [],
    'SENTBEFORE': ['date'],
    'SENTON': ['date'],
    'SENTSINCE': ['date'],
    'SINCE': ['date'],
    'SMALLER': ['n'],
    'SUBJECT': ['string'],
    'TEXT': ['string'],
    'TO': ['string'],
    'UID': ['sequence set'],
    'UNANSWERED': [],
    'UNDELETED': [],
    'UNDRAFT': [],
    'UNFLAGGED': [],
    'UNKEYWORD': ['flag'],
    'UNSEEN': []
    }


def c2s_command_line_parse(data):
    """
    Input must be bytes.

    If parsing failed - None is returned.

    On success, dict is returned:
        {
            'tag': str,
            'command': str # upper cased,
            'parameters': bytes # parameters are too complex, so must be
                                # treated individually by each command
            }
    """

    if not isinstance(data, bytes):
        raise TypeError("`data' type must be bytes")

    if not data.endswith(wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR):
        raise TypeError(
            "`data' must be termenated with `{}'".format(
                wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
                )
            )

    ret = None

    data = data[:-2]

    res = data.split(b' ', 1)

    parsing_error = False

    if len(res) < 2:
        parsing_error = True
    else:
        tag, data = res
        res = data.split(b' ', 1)
        len_res = len(res)
        if len_res == 1:
            command = res[0]
            parameters = None
        else:
            command, parameters = res

    if parsing_error:
        ret = None

    else:

        tag = str(tag, 'utf-8')
        command = str(command, 'utf-8')
        command = command.upper()

        ret = {
            'tag': tag,
            'command': command,
            'parameters': parameters
            }

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


def receive_string_literal(
        lbl_reader,
        size,
        permanent_variable,
        sock,
        is_server,
        stop_event,
        bs=512
        ):

    success = True

    if is_server:
        wayround_org.utils.socket.nb_sendall(
            sock,
            b'+ Ready for literal data' +
            wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
            )

    int_size_bs = int(size / bs)

    with permanent_variable.open('bw') as pv:

        buf_size = 0

        for i in range(int_size_bs):
            if stop_event is not None and stop_event.is_set():
                success = False
                break
            buf = lbl_reader.nb_get_next_bytes(
                bs,
                stop_event=stop_event
                )
            if buf is None:
                success = False
                break
            pv.write(buf)
            buf_size += len(buf)
            del buf

        if success:
            buf = self.lbl_reader.nb_get_next_bytes(
                size - (bs * int_size_bs),
                stop_event=stop_event
                )
            if buf is None:
                success = False
            else:
                pv.write(buf)
                buf_size += len(buf)

    return success


def parse_string_literal_param(
        parameters_bytes,
        lbl_reader,
        permanent_memory,
        sock,
        is_server,
        stop_event
        ):

    if not isinstance(
            permanent_memory,
            wayround_org.utils.pm.PermanentMemory
            ):
        raise TypeError(
            "`permanent_memory' must be inst of "
            "wayround_org.utils.pm.PermanentMemory"
            )

    if not isinstance(parameters_bytes, bytes):
        raise ValueError("`parameters_bytes' must be bytes")

    if parameters_bytes[0] != ord(b'{'):
        raise ValueError("`parameters_bytes' is not size")

    closing_brace = parameters_bytes.find(b'}')

    if closing_brace == -1 or closing_brace <= 1:
        raise ValueError("`parameters_bytes' size format is invalid")

    size = int(str(parameters_bytes[1:closing_brace], 'utf-8'))

    permanent_variable = permanent_memory.new()

    res = receive_string_literal(
        lbl_reader,
        size,
        permanent_variable,
        sock,
        is_server,
        stop_event
        )

    ret = None
    cmd_line_continue = b''

    if res is True:
        ret = permanent_variable
        cmd_line_continue = self.lbl_reader.nb_get_next_line(stop_event)

    return ret, cmd_line_continue


def _parse_string_param_find_closing_quote(parameters_bytes):
    """
    parameters_bytes bust be bytes.
    if len(parameters_bytes) is not 0, then parameters_bytes[0] must be eq b'"'

    return: -1 - not found.
    """
    ret = -1  # Not found by default

    if len(parameters_bytes) == 0:
        raise ValueError("this function requires len(parameters_bytes) > 0")

    if parameters_bytes[0] != ord(b'"'):
        raise ValueError(
            "first char of parameters_bytes must be `\"' (double quote)"
            )

    if parameters_bytes[1] == ord(b'"'):
        ret = 1

    if ret == -1:
        i = 2
        len_parameters_bytes = len(parameters_bytes)
        found = None
        while True:
            if i == len_parameters_bytes:
                break
            # TODO: probably this could be done with regexp
            if parameters_bytes[i] == ord(b'"'):
                if parameters_bytes[i - 1] == ord(b'\\'):
                    if parameters_bytes[i - 2] == ord(b'\\'):
                        found = i
                        break
                    else:
                        pass
                else:
                    found = i
                    break
            i += 1

        if found is not None:
            ret = found

    return ret


def parse_string_param(parameters_bytes, stop_event):

    if not isinstance(parameters_bytes, bytes):
        raise ValueError("`parameters_bytes' must be bytes")

    ret = None
    next_ind = None

    if parameters_bytes[0] == ord(b'"'):

        quote_index = _parse_string_param_find_closing_quote(parameters_bytes)

        if quote_index == -1:
            pass

        else:
            ret = parameters_bytes[1:quote_index]
            next_ind = quote_index + 1

    else:

        quote_index = parameters_bytes.find(b' ')

        if quote_index == -1:
            ret = parameters_bytes
            next_ind = len(parameters_bytes)

        else:
            ret = parameters_bytes[:quote_index]
            next_ind = quote_index + 1

    return ret, next_ind


def parse_flags_param(parameters_bytes, stop_event):
    """
    ret: None - error or limit on baximum parameters count

    """

    if not isinstance(parameters_bytes, bytes):
        raise ValueError("`parameters_bytes' must be bytes")

    len_parameters_bytes = len(parameters_bytes)

    if len_parameters_bytes > 0:
        if parameters_bytes[0] != ord(b'('):
            raise ValueError("invalid `parameters_bytes'")

    end_index = None

    i = 0

    while True:
        if stop_event is not None and stop_event.is_set():
            break
        if i == len_parameters_bytes:
            break
        if parameters_bytes[i] == ord(b')'):
            end_index = i + 1
            break
        i += 1

    if end_index is None:
        raise ValueError("invalid params")

    # ret = parameters_bytes[:end_index][1:-1].split(b' ')

    ret = parameters_bytes[:end_index]
    del parameters_bytes
    ret = ret[1:-1]
    ret = ret.split(b' ')
    for i in range(len(ret)):
        ret[i] = str(ret[i], 'utf-7')

    return ret, end_index


def is_cmd_line_end(parameters_bytes):
    ret = False
    if (parameters_bytes
            == wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR):
        ret = True

    if not ret:
        if len(parameters_bytes) == 0:
            ret = True
    return ret


def remove_left_spaces(parameters_bytes, stop_event):
    while True:
        if stop_event is not None and stop_event.is_set():
            break

        if is_cmd_line_end(parameters_bytes):
            break

        if parameters_bytes[0] == ord(b' '):
            parameters_bytes = parameters_bytes[1:]
        else:
            break
    return parameters_bytes


def parse_parameters(
    parameters_bytes,
    lbl_reader,
    permanent_memory,
    sock,
    is_server,
    stop_event=None
        ):

    ret = []

    while True:

        parameters_bytes = remove_left_spaces(parameters_bytes, stop_event)

        if stop_event is not None and stop_event.is_set():
            break

        if is_cmd_line_end(parameters_bytes):
            break

        if parameters_bytes[0] == ord(b'('):
            res, start_index = parse_flags_param(
                parameters_bytes,
                stop_event=stop_event
                )
            ret.append(
                {'type': 'flags', 'value': res}
                )
            parameters_bytes = parameters_bytes[start_index:]
        elif parameters_bytes[0] == ord(b'{'):
            res, parameters_bytes = parse_string_literal_param(
                parameters_bytes,
                lbl_reader,
                permanent_memory,
                sock,
                is_server,
                stop_event
                )
            ret.append(
                {'type': 'string_literal', 'value': res}
                )

        else:
            res, start_index = parse_string_param(
                parameters_bytes,
                stop_event=stop_event
                )
            ret.append(
                {'type': 'string', 'value': res}
                )
            parameters_bytes = parameters_bytes[start_index:]

    return ret


def sumarize_parsed_parameters(list_of_dicts):

    size = None
    flags = set()
    strings = []

    for i in list_of_dicts:
        if i['type'] == 'flags':
            flags = i['value']
        elif i['type'] in ['string', 'string_literal']:
            strings.append(i['value'])
        else:
            raise ValueError("invalid i['type']: {}".format(i['type']))

    ret = {
        'flags': flags,
        'strings': strings
        }

    return ret


def parse_parameters_sumarized(
        parameters_bytes,
        lbl_reader,
        permanent_memory,
        sock,
        is_server,
        stop_event=None
        ):
    """
    c2s - set to true if client to server mode required.
    """
    list_of_dicts = parse_parameters(
        parameters_bytes,
        lbl_reader,
        permanent_memory,
        sock,
        is_server,
        stop_event=stop_event
        )
    ret = sumarize_parsed_parameters(list_of_dicts)
    return ret


def quote(value):
    value = value.replace('\\', '\\\\')
    value = value.replace('"', '\\"')
    return value


def unquote(value):
    # TODO: to do
    return


def format_mailbox_status_text(
        flags, exists, recent, unseen,
        permanentflags,
        uidnext, uidvalidity
        ):

    ret = b''

    if flags is not None:
        ret += bytes(
            '* FLAGS ({})'.format(' '.join(flags)), 'utf-8'
            )
        ret += wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

    if exists is not None:
        ret += bytes(
            '* {} EXISTS'.format(exists), 'utf-8'
            )
        ret += wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

    if recent is not None:
        ret += bytes(
            '* {} RECENT'.format(recent), 'utf-8'
            )
        ret += wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

    return ret


def c2s_search_parameters_parse(parameters_bytes, stop_event):

    while True:

        if stop_event is not None and stop_event.is_set():
            break

        if len(parameters_bytes) == 0:
            break

        if parameters_bytes[0] != ord(b' '):
            break

        parameters_bytes = parameters_bytes[1:]

    search_acceptable_keywords = []

    value_of_CHARSET = None

    error_bad = False

    spl_res = parameters_bytes.split(b' ', 1)
    if len(spl_res) > 1:
        part, _t_pb = spl_res
        if part.upper() == b'CHARSET':
            spl_res = _t_pb.split(b' ', 1)
            if len(spl_res) > 1:
                part, parameters_bytes = spl_res
                value_of_CHARSET = str(part, 'utf-8')
            else:
                error_bad = True
        del _t_pb

    if not error_bad:

        while True:

            while True:

                if stop_event is not None and stop_event.is_set():
                    break

                if len(parameters_bytes) == 0:
                    break

                if parameters_bytes[0] != ord(b' '):
                    break

                parameters_bytes = parameters_bytes[1:]

            if stop_event is not None and stop_event.is_set():
                break

            if len(parameters_bytes) == 0:
                break

            spl_res = parameters_bytes.split(b' ', 1)

            len_spl_res = len(spl_res)

            if len_spl_res == 0:
                break
            elif len_spl_res == 1:
                cmd = spl_res[0]
                parameters_bytes = b''
            else:
                cmd, parameters_bytes = spl_res

            cmd = str(cmd, 'utf-8').upper()

            if not cmd in IMAP_SEARCH_KEYS:
                error_bad = True
                break

    return ret

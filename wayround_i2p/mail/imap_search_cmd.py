
"""
IMAP SEARCH command has complex structure and parsing context requirements
so it's functionality separated into own module
"""

import wayround_i2p.mail.imap


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
    'HEADER': ['string', 'string'],
    'KEYWORD': ['flag'],
    'LARGER': ['n'],
    'NEW': [],
    'NOT': ['search-key'],
    'OLD': [],
    'ON': ['date'],
    'OR': ['search-key', 'search-key'],
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


def parse_search_cmdline_bytes(
        parameters_bytes,
        stop_event,
        till_closing_brace=False  # set this to True if u staring this function
                                  # because of '('
        ):

    ret = []
    bad = False

    while True:

        if parameters_bytes[0] == ord(b')'):
            if till_closing_brace:
                parameters_bytes = parameters_bytes[1:]
                break
            else:
                # if closing brace is not expected, then this is an error
                bad = True
                break

        if bad is True:
            break

        if stop_event is not None and stop_event.is_set():
            break

        if wayround_i2p.mail.imap.is_cmd_line_end(parameters_bytes):
            break

        parameters_bytes = wayround_i2p.mail.imap.remove_left_spaces(
            parameters_bytes,
            stop_event
            )

        key = None
        values = []

        if parameters_bytes[0] == ord(b'('):
            key = '('
            values, parameters_bytes, bad = parse_search_cmdline_bytes(
                parameters_bytes[1:],
                stop_event
                )
        else:
            key, start_index = wayround_i2p.mail.imap.parse_string_param(
                parameters_bytes,
                stop_event=stop_event
                )
            if bad is True:
                break
            parameters_bytes = parameters_bytes[start_index:]

            del start_index

            key = str(key, 'utf-8').upper()

            if not key in IMAP_SEARCH_KEYS:
                bad = True
                break

            # len_IMAP_SEARCH_KEYS_key =len(IMAP_SEARCH_KEYS[key])

            for i in IMAP_SEARCH_KEYS[key]:
                if i == 'string':
                    if parameters_bytes[0] == ord(b'{'):
                        res, parameters_bytes = \
                            wayround_i2p.mail.imap.parse_string_literal_param(
                                parameters_bytes,
                                lbl_reader,
                                permanent_memory,
                                sock,
                                is_server,
                                stop_event
                                )
                        values.append(res)
                        del res

                    else:
                        res, start_index = \
                            wayround_i2p.mail.imap.parse_string_param(
                                parameters_bytes,
                                stop_event=stop_event
                                )
                        values.append(res)
                        parameters_bytes = parameters_bytes[start_index:]
                        del res
                        del start_index

                else:
                    raise Exception("Programming error")

        ret.append({'key': key, 'values': values})

    return ret, parameters_bytes, bad


class SearchKey:

    def __init__(self, key, values):
        return

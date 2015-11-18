

"""
The main difference between this module and wayround_org.http.message
is what http is as streaming protocol, unlike e-mail, which is
message oriented.
"""


import wayround_org.http.message


MAX_LINE_LENGTH = 998
RECOMMENDED_LINE_WRAP_LENGTH = 78

STANDARD_FIELDS = [
    'Date', 'From', 'Sender', 'Reply-To', 'To', 'Cc', 'Bcc', 'Message-ID',
    'In-Reply-To', 'References', 'Subject', 'Comments', 'Keywords',
    'Resent-Date', "Resent-From", "Resent-Sender", "Resent-To",
    "Resent-Cc", "Resent-Bcc", "Resent-Message-ID"
    ]
FIELD_MINIMUM_COUNT_ONE = [
    'Date', 'From'
    ]
FIELD_MAXIMUM_COUNT_ONE = [
    'Date', 'From', 'Sender', 'Reply-To', 'To', 'Cc', 'Bcc', 'Message-ID',
    'In-Reply-To', 'References', 'Subject'
    ]


class MessageTooLongLines(Exception):
    pass


class MessageRequiredFieldMissing(Exception):
    pass


class MessageExceedField(Exception):
    pass


class MessageCantFindColumnInLine(Exception):
    pass


class MessageNoCommentEnd(Exception):
    pass


class MessageBodyLineTooLong(Exception):
    pass


class MessageBodyLineInvalidCharacter(Exception):
    pass


class MessageSourceInvalidWrap(Exception):
    pass


def parse_message_source_text(
        text,
        max_line_length=MAX_LINE_LENGTH,
        line_separator=b'\r\n'
        ):
    """
    `text' value must be bytes because RFC5322 talking all the time
    only about US-ASCII [ANSI.X3-4.1986] data. And line lengths works on
    bytes, not on unicode letters.

    For Unicode (python str type), there will be spetial classes or functions
    (but they are not present at the current development time).

    line_separator can not have other values than in [b'\\r\\n', b'\\n']

    If line_separator == b'\\r\\n' (this is standard situation),
    then this function checks supplied text for correct line wrappings:
    \\r must be before \\n, \\n must be after \\r. Exception is raised if this
    is not so.

    If line_separator == b'\\n', then lines will be separated by b'\\n', and
    b'\\r's, if whem is indead in text, will be left untouched. You will need to
    do some other actions to remove b'\\r's from text.. This module has function
    for removing b'\\r's from supplied text, and You can use it before passing
    text to parse_message_source_text().

    By default line_separator == b'\\r\\n', - this is standard, but many mail
    software implimentations do not obey standards (even Mozilla Thunderbird)
    and employ b'\\n' as lineseparator.
    """

    if not isinstance(text, bytes):
        raise TypeError("`text' value type must be bytes")

    if not line_separator in [b'\r\n', b'\n']:
        raise ValueError("invalid `line_separator'")

    if line_separator == b'\r\n':
        validate_rn_separated_text(text)

    # ==== Header routines ====

    header_fields = []

    lines = wayround_org.http.message.split_lines(text, line_separator)
    lines_l = len(lines)

    for i in range(lines_l):
        if len(lines[i]) > max_line_length:
            raise MessageTooLongLines("too long line no: {}".format(i))

    i = -1
    while True:

        if i + 1 >= lines_l:
            break

        i += 1

        line_i = lines[i]

        if line_i == b'':
            break

        column_index = line_i.find(b':')
        if column_index == -1:
            raise MessageCantFindColumnInLine(
                "can't find `:' in line no: {}".format(i)
                )

        name = line_i[:column_index]
        value = [line_i[column_index + 1:]]

        ii = i
        while True:
            if ii + 1 >= lines_l:
                i = ii
                break
            if lines[ii + 1].startswith(b' '):
                value.append(lines[ii + 1])
                ii += 1
            else:
                i = ii
                break

        header_fields.append((name, value,))

    # ==== Body routines ====

    body_lines = lines[i + 1:]

    if body_lines[-1] == b'':
        body_lines = body_lines[:-1]

    return header_fields, body_lines


def render_message_source_text(
        header_fields,
        body_lines,
        max_line_length=MAX_LINE_LENGTH,
        recommended_line_wrap_length=RECOMMENDED_LINE_WRAP_LENGTH,
        line_separator=b'\r\n'
        ):

    if not line_separator in [b'\r\n', b'\n']:
        raise ValueError("invalid `line_separator'")

    ret = b''

    for i in header_fields:
        ret += i[0]
        ret += b':'
        for j in i[1]:
            ret += j
            ret += line_separator

    ret += line_separator

    for i in body_lines:
        ret += i
        ret += line_separator

    return ret


def determine_line_separator(text):
    return wayround_org.http.message.determine_line_terminator(text)


def determine_line_separator_in_stream(stream):
    """
    Returns first line and it's terminator: tuple(terminator, bytes)
    """

    first_line = b''

    line_separator = None

    while True:
        res = stream.read(1)

        first_line += res

        if res == 13:
            line_separator = determine_line_separator(first_line)
            break

    return line_separator, first_line.strip()


def wrap_lines(
        text,
        first_line_length,
        recommended_line_wrap_length=RECOMMENDED_LINE_WRAP_LENGTH,
        line_separator=b'\r\n'
        ):

    if not isinstance(text, bytes):
        raise TypeError("`text' value type must be bytes")

    if not line_separator in [b'\r\n', b'\n']:
        raise ValueError("invalid `line_separator'")

    # TODO

    return


def remove_rs_from_text(text):
    ret = text
    while b'\r' in ret:
        ret.remove(b'\r')
    return ret


def validate_rn_separated_text(text):

    if not isinstance(text, bytes):
        raise TypeError("`text' value type must be bytes")

    text_l = len(text)

    for j in range(text_l):
        text_char = text[j]

        if text_char == b'\r':
            if j >= text_l or text[j + 1] != b'\n':
                raise MessageSourceInvalidWrap(
                    "\\r must be suffixed with \\n, "
                    "but it's not at byte {}".format(i)
                    )

        if body_line_char == b'\n':
            if j == 0 or body_line[j - 11] != b'\r':
                raise MessageSourceInvalidWrap(
                    "\\n must be prefixed with \\r, "
                    "but it's not at byte {}".format(i)
                    )

    return


def validate_header(header_fields):

    """
    result: True - ok, False - errors found
    """

    errors = 0

    for i in FIELD_MINIMUM_COUNT_ONE:
        count = 0
        for j in header_fields:
            if j[0].lower().strip() == i:
                count += 1
        if count < 1:
            errors += 1
            '''
            raise MessageRequiredFieldMissing(
                "field `{}' must be found in message atleast one time".format(
                    i
                    )
                )
            '''

    for i in FIELD_MAXIMUM_COUNT_ONE:
        count = 0
        for j in header_fields:
            if j[0].lower().strip() == i:
                count += 1
        if count > 1:
            errors += 1
            '''
            raise MessageExceedField(
                "field `{}' count must be not bigger then one".format(
                    i
                    )
                )
            '''

    return


def validate_body(body_lines):

    body_lines_l = len(body_lines)

    for i in range(body_lines_l):

        body_line = body_lines[i]

        if len(body_line) > max_line_length:
            raise MessageBodyLineTooLong("body line {} too long".format(i))

        validate_rn_separated_text(body_line)

    return


def unwrap_header_bodies(header_fields):
    ret = []
    for i in header_fields:
        ret.append(i[0], b''.join(i[1]),)
    return ret


def _find_comment_end(text, comments_list, start):
    """
    `start' must be index of comment_start (the `(' character not quotted by
    preciding back slash)

    upon succes an index of closing `)' + 1 is returned and range object
    (which is index of opening ( and index of closing ) + 1)
    is added to comments_list

    if end not found, it is considdered an error and exception is raised.

    this function is not intended for direct usage. It's only intended as
    subroutine for other functions
    """

    ret = None

    text_l = len(text)

    i = start

    while True:
        if i >= text_l:
            break

        if text[i] == b')' and (i > 0 and text[i - 1] != b'\\'):
            ret = i + 1
            break

        if text[i] == b'(' and (i > 0 and text[i - 1] != b'\\'):
            i = _find_comment_end(text, comments_list, i)

        i += 1

    if ret is None:
        raise MessageNoCommentEnd(
            "can't find comment end started at index: {}".format(start)
            )

    if ret is not None:
        comments_list.append(range(start, ret))

    return ret


def find_comments(text):
    """
    Searches for comments and returns list of ranges

    `text' must be bytes
    """

    comments_list = []

    text_l = len(text)

    i = 0

    while True:
        if i >= text_l:
            break

        if text[i] == b'(' and (i > 0 and text[i - 1] != b'\\'):
            i = _find_comment_end(text, comments_list, i)

        i += 1

    return ret


def merge_overlapping_comments(comments_list):
    ret = []

    for i in comments_list:
        found = False
        for j in ret:

            if i.start in j or i.end in j:

                j_index = ret.index(j)

                if i.start in j and not i.end in j:
                    ret[j_index] = range(j.start, i.end)
                    j = ret[j_index]

                if i.end in j and not i.start in j:
                    ret[j_index] = range(i.start, j.end)
                    j = ret[j_index]

                found = True
                break

        if not found:
            ret.append(i)

    return ret


def sort_comments(comments_list):
    ret = copy.copy(comments_list)
    ret.sort(key=lambda x: x.start)
    return ret


def remove_comments_from_text(text, comments_list):
    """
    comments_list: overlappings must be merged, values must be sorted.
    """
    ret = text
    for i in range(len(comments_list) - 1, -1, 1):
        ret = ret[:i.start] + ret[i.end:]
    return ret


def unquote_pairs(text):
    """
    Unquotes pairs
    """

    # TODO

    return


def field_value_to_text(text):
    """
    Converts source field value to normal text

    Removind comments and unquotting quotted pairs

    `text' must be bytes
    """

    # TODO

    return

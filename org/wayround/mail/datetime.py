
import re
import datetime

import org.wayround.utils.datetime_iso8601


MONTH = [
    "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec"
    ]


DATETIME_TEXT_REGEXP = re.compile(
    r'\s*((?P<day_name>\w{3}) *,)?'
    r'\s*(?P<day>\d{1,2}) (?P<month_name>\w{3}) (?P<year>\d{4})\s*'
    r'\s*(?P<hour>\d{2})\:(?P<minute>\d{2})(\:(?P<second>\d{2}))?\s*'
    r'\s*(?P<tz>(?P<sign>[+-])?(?P<tzhour>\d{2})(?P<tzminute>\d{2}))\s*'
    )


def str_to_datetime(text):

    if not isinstance(text, (bytes, str)):
        raise TypeError("`text' value type must be str or bytes")

    if isinstance(text, bytes):
        text = str(text, 'utf-8')

    ret = None
    res = DATETIME_TEXT_REGEXP.match(text)
    if res is not None:
        d = {}
        for i in [
                'day_name',
                'day',
                'month_name',
                'year',
                'hour',
                'minute',
                'second',
                'tz',
                'sign',
                'tzhour',
                'tzminute'
                ]:
            d[i] = res.group(i)

        for i in [
                'day',
                'year',
                'hour',
                'minute',
                'second',
                'tzhour',
                'tzminute'
                ]:
            if d[i] is not None:
                d[i] = int(d[i])

        m_name = d['month_name'][:1].upper() + d['month_name'][1:].lower()
        d['month'] = MONTH.index(m_name) + 1

        tz = org.wayround.utils.datetime_iso8601.gen_tz(
            d['tzhour'],
            d['tzminute'],
            d['sign'] != '-'
            )

        ret = datetime.datetime(
            d['year'],
            d['month'],
            d['day'],
            d['hour'],
            d['minute'],
            d['second'],
            0,
            tz
            )

    return ret

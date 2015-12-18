
import pprint

import org.wayround.mail.datetime
import org.wayround.utils.datetime_iso8601

val = b'Thu, 05 Jun 2014 00:38:33 +0400'

res = org.wayround.mail.datetime.str_to_datetime(val)

res_str = org.wayround.utils.datetime_iso8601.datetime_to_str(res)
res_str2 = org.wayround.mail.datetime.datetime_to_str(res)


print("input: {}".format(val))
print("    parse result: {}".format(pprint.pformat(res)))

print("    {}".format(res_str))
print("    {}".format(res_str2))

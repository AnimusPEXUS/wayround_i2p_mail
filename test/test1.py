
import pprint

import org.wayround.mail.message

txt = b"""\
Message-ID: <538F83C9.2000102@wayround.org>
Date: Thu, 05 Jun 2014 00:38:33 +0400
From: Alexey V Gorshkov <animus@wayround.org>
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:28.0) Gecko/20100101
 Firefox/28.0 SeaMonkey/2.25
MIME-Version: 1.0
To: Alexey V Gorshkov <animus@wayround.org>
Subject: test2
Content-Type: text/plain; charset=ISO-8859-1; format=flowed
Content-Transfer-Encoding: 7bit
X-Evolution-Source: 1363552882.31897.3@agutilities

test2
"""

# txt = org.wayround.mail.message.remove_rs_from_text(txt)

print('src test:\n======\n{}\n======\n'.format(txt))

line_separator = org.wayround.mail.message.determine_line_separator(txt)

print("line_separator is: {}".format(repr(line_separator)))

header_fields, body_lines = \
    org.wayround.mail.message.parse_message_source_text(
        txt,
        line_separator=line_separator
    )

res_rendered = org.wayround.mail.message.render_message_source_text(
    header_fields, body_lines,
    line_separator=line_separator
    )


print(
    "parsed:\n======\n{}\n======\n{}\n======\n".format(
        header_fields,
        body_lines
        )
    )
print("rendered:\n======\n{}\n======\n".format(res_rendered))

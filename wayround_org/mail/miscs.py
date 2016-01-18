
import wayround_org.utils.uri

STANDARD_LINE_TERMINATOR = b'\r\n'

MAX_LINE_LENGTH = 998  # according to RFC
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


class Address:

    @classmethod
    def new_from_str(cls, value):

        if not isinstance(value, str):
            raise TypeError("`value' must be str")

        less_sign = value.find('<')
        more_sign = value.find('>')

        authority = None
        title = None

        if less_sign != -1:

            if more_sign <= less_sign:
                raise ValueError("invalid mail address title")

            title = value[:less_sign] + value[more_sign + 1:]
            title = title.strip()

            authority = value[less_sign + 1:more_sign]

        else:

            authority = value

        return cls(authority, title)

    @classmethod
    def new_from_dict(cls, value):
        return cls(value['authority'], value.get('title'))

    def __init__(self, authority, title=None):

        self._authority = None
        self._title = None

        self.authority = authority
        self.title = title

        return

    @property
    def authority(self):
        return self._authority

    @authority.setter
    def authority(self, value):
        if isinstance(value, str):
            value = wayround_org.utils.uri.AuthorityLikeHttp.new_from_string(
                value
                )

        if not isinstance(value, wayround_org.utils.uri.AuthorityLikeHttp):
            raise TypeError(
                "`authority' must be str or inst of "
                "wayround_org.utils.uri.AuthorityLikeHttp"
                )

        self._authority = value

        return

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        if value is not None and not isinstance(value, str):
            raise TypeError("`title' must be None or str")
        self._title = value
        return

    def render_dict(self):
        ret = {
            'authority': self.authority.render_str(),
            'title': self.title
            }
        return ret

    def render_str(self):

        ret = self.authority.render_str()

        if self.title is not None:
            ret = '{} <{}>'.format(self.title, ret)

        return ret

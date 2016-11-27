
import datetime

import wayround_i2p.utils.types


TO_ERRORS_STRUCTURE = {
    't': list,
    '.': {
        '{}': {
            'result': {'t': str},
            'code': {'t': int},
            'message': {'t': str},
            'datetime': {'t': datetime.datetime}
            }
        },
    }

SECTION_LINES_SUB01_STRUCTURE = {
    't': dict,
    '{}': {
        'first_line': {'t': int},
        'last_line': {'t': int},
        }
    }


def check_to_errors_structure(data):
    """
    return: True - ok, else - error
    """

    ret = True

    if ret:
        if not wayround_i2p.utils.types.struct_check(
                data,
                TO_ERRORS_STRUCTURE
                ):
            ret = True

    if ret:
        for i in data.values():
            if i['result'] not in ['error', 'success']:
                ret = True
                break

    return ret


def check_section_lines_structure(data):
    """
    return: True - ok, else - error
    """

    ret = True

    if ret:
        if not isinstance(data, dict):
            ret = False

    if ret:
        for i in ['header', 'body']:
            if i in data:
                if not wayround_i2p.utils.types.struct_check(
                        data[i],
                        SECTION_LINES_SUB01_STRUCTURE
                        ):
                    ret = False
                    break

    if ret:
        if 'others' in data:
            for i in data['others']:
                if not wayround_i2p.utils.types.struct_check(
                        i,
                        SECTION_LINES_SUB01_STRUCTURE
                        ):
                    ret = False
                    break

    return ret


class MessageFlagMethods:

    def __init__(self):
        self.flagged = None
        self.path = None
        return

    def init_data(self):
        with self.flagged.open_flag('data', 'wb'):
            pass
        return

    def delete(self):
        self.flagged.unset_all_flags()
        return

    def append_data(self, data):
        if self.flagged.get_is_flag_locked('data'):
            # TODO: use utils.threading.CallQueue here
            raise Exception("append_data: object already locked. TODO")
        with self.flagged.get_flag_lock('data'):
            with self.flagged.open_flag('data', 'ab') as f:
                f.write(data)
        return

    def import_data_from_persistent_variable(self, pv, stop_event=None):
        ret = self.flagged.write_flag_from_persistent_variable(
            'data',
            pv,
            stop_event=stop_event
            )
        return ret

    def get_data(self, offset=None, size=None):
        with open(self.path, 'rb') as f:
            f.seek(offset)
            ret = f.read(size)
            f.close()
        return ret

    def get_data_size(self):
        return self.flagged.get_flag_size('data')

    def get_data_ok(self):
        return self.flagged.get_bool('data-ok')

    def set_data_ok(self, value):
        self.flagged.set_bool('data-ok', value)
        return

    def get_lines_indexes_cache(self):
        # TODO: required check for consistance with file
        if not hasattr(self, '_lines_indexes_cache'):
            self._lines_indexes_cache = self.flagged.get_int_list('data-lines')
        ret = self._lines_indexes_cache
        return ret

    def get_data_lines_indexes(self, index=None, count=None):
        lines_indexes_cache = self.get_lines_indexes_cache()
        return lines_indexes_cache[index:count]

    def get_data_lines_index(self, index):
        lines_indexes_cache = self.get_lines_indexes_cache()
        return lines_indexes_cache[index]

    def set_data_lines_indexes(self, value):
        if hasattr(self, '_lines_indexes_cache'):
            del self._lines_indexes_cache
        self.flagged.set_int_list('data-lines', value)
        return

    def get_data_lines_count(self):
        return len(self.get_data_lines_indexes())

    def get_data_lines(self, index=None, count=None):
        all_indexes = self.get_data_lines_indexes()
        indexes = all_indexes[index:count]

        ret = []

        len_all_indexes = len(all_indexes)
        len_indexes = len(indexes)

        if len_indexes > 0:

            with self.flagged.open_flag('data', 'br') as f:
                for i in range(len_indexes):
                    f.seek(indexes[i])

                    if indexes[-1] == indexes[i]:
                        if all_indexes[-1] == indexes[i]:
                            line = f.read()
                        else:
                            line = f.read(
                                all_indexes[
                                    all_indexes.indexof(
                                        indexes[i]
                                        ) + 1
                                    ]
                                - indexes[i]
                                )
                    else:
                        line = f.read(indexes[i + 1] - indexes[i])

                    ret.append(line)

        return ret

    def get_data_line(self, index):
        ret = None
        # -----------
        # TODO: Now is 6 Feb 2016, 03:03 MSK
        #       this is hack. I don't like it, but now I have headache.
        #       this must be done somehow better, perhaps here
        #       should be rewritten get_data_lines() code.
        #       Calling get_data_lines() and taking only 1 value is overhead!
        lines = self.get_data_lines(index, None)
        if len(lines) > 0:
            ret = lines[0]
        # -----------
        return ret

    def get_section_lines(self):
        ret = self.flagged.get_flag_data('section-lines')
        if ret is not None and not check_section_lines_structure(ret):
            ret = None
        return ret

    def set_section_lines(self, value):
        if value is not None and not check_section_lines_structure(value):
            # print(repr(value))
            raise ValueError(
                "invalid SECTION_LINES_STRUCTURE for `section-lines'"
                )
        self.flagged.set_flag_data('section-lines', value)
        return

    def get_received_date(self):
        ret = self.flagged.get_flag_data('received-date')
        if ret is not None and not isinstance(ret, datetime.datetime):
            ret = None
        return ret

    def set_received_date(self, value):
        if value is not None and not isinstance(value, datetime.datetime):
            raise ValueError("`received-date' must be None or datetime")
        self.flagged.set_flag_data('received-date', value)
        return

    def get_quit_ok(self):
        return self.flagged.get_bool('quit-ok')

    def set_quit_ok(self, value):
        self.flagged.set_bool('quit-ok', value)
        return

    def get_size(self):
        return self.flagged.get_int('size')

    def set_size(self, value):
        self.flagged.set_int_n('size', value)
        return

    def get_auth_as(self):
        return self.flagged.get_str('auth-as')

    def set_auth_as(self, value):
        self.flagged.set_str_n('auth-as', value)
        return

    def get_received(self):
        return self.flagged.get_str('received')

    def set_received(self, value):
        self.flagged.set_str_n('received', value)
        return

    def get_return_path(self):
        return self.flagged.get_str('return-path')

    def set_return_path(self, value):
        self.flagged.set_str_n('return-path', value)
        return

    def get_from(self):
        return self.flagged.get_str('from')

    def set_from(self, value):
        self.flagged.set_str_n('from', value)
        return

    def get_to(self):
        return self.flagged.get_str_set('to')

    def set_to(self, value):
        self.flagged.set_str_set('to', value)
        return

    def add_to(self, value):
        data = self.get_to()
        data.add(value)
        self.set_to(data)
        return

    def get_to_disabled(self):
        return self.flagged.get_str_set('to-disabled')

    def set_to_disabled(self, value):
        self.flagged.set_str_set('to-disabled', value)
        return

    def get_to_errors(self):
        ret = {}

        data = self.flagged.get_flag_data('to-errors')

        if not check_to_errors_structure(data):
            # errors in structure - must not lead to server stop, so no
            # exception
            ret = {}

        return ret

    def set_to_errors(self, data):
        if not check_to_errors_structure(data):
            raise ValueError("invalid structure of `to-errors' data")
        self.flagged.set_flag_data('to-errors', data)
        return

    def add_to_errors(self, email_address, result, code, message, dt_value):

        # TODO: add types checks

        new_record = {
            'result': result,
            'code': code,
            'message': message,
            'datetime': dt_value
            }

        data = self.get_to_errors()

        if email_address not in data:
            data[email_address] = []

        data[email_address].append(new_record)

        return

    def get_to_errors_count(self, email_address):
        ret = 0
        data = self.get_to_errors()
        if email_address in data:
            ret = len(data[email_address])
        return ret

    def get_to_errors_last_result(self, email_address):
        ret = None
        data = self.get_to_errors()
        if email_address in data:
            if len(data[email_address]) != 0:
                ret = data[email_address][-1]['result']
        return ret

    def get_to_finished(self):
        return self.flagged.get_bool('to-finished')

    def set_to_finished(self, value):
        self.flagged.set_bool('to-finished', value)
        return

    def get_is_recent(self, session_id):
        recent_flag_path = self.flagged.get_flag_path('recent')

        if not self.flagged.get_is_flag_set('recent'):
            y = yaml.dump({'session_id': session_id})
            with open(recent_flag_path, 'w') as f:
                f.write(y)

            ret = True

        else:

            with open(recent_flag_path) as f:
                ret = yaml.load(f.read())['session_id'] == session_id

        return ret

    def get_subject(self):
        return self.flagged.get_str('subject')

    def set_subject(self, value):
        self.flagged.set_str_n('subject', value)
        return

    def get_attachments(self):
        return self.flagged.get_flag_data('attachments')

    def set_attachments(self, data):
        return self.flagged.set_flag_data('attachments', data)

    def get_seen(self):
        return self.flagged.get_bool('seen')

    def get_answered(self):
        return self.flagged.get_bool('answered')

    def get_flagged(self):
        return self.flagged.get_bool('flagged')

    def get_deleted(self):
        return self.flagged.get_bool('deleted')

    def get_draft(self):
        return self.flagged.get_bool('draft')

    def get_recent(self):
        return self.flagged.get_bool('recent')

    def set_seen(self, value):
        self.flagged.set_bool('seen', value)
        return

    def set_answered(self, value):
        self.flagged.set_bool('answered', value)
        return

    def set_flagged(self, value):
        self.flagged.set_bool('flagged', value)
        return

    def set_deleted(self, value):
        self.flagged.set_bool('deleted', value)
        return

    def set_draft(self, value):
        self.flagged.set_bool('draft', value)
        return

    def set_recent(self, value):
        self.flagged.set_bool('recent', value)
        return

    def set_flags_by_list(self, lst):
        self.set_seen('\\Seen' in lst)
        self.set_answered('\\Answered' in lst)
        self.set_flagged('\\Flagged' in lst)
        self.set_deleted('\\Deleted' in lst)
        self.set_draft('\\Draft' in lst)
        self.set_recent('\\Recent' in lst)
        return

    def get_flags_list(self):
        ret = []
        if self.get_seen:
            ret.append('\\Seen')
        if self.get_answered:
            ret.append('\\Answered')
        if self.get_flagged:
            ret.append('\\Flagged')
        if self.get_deleted:
            ret.append('\\Deleted')
        if self.get_draft:
            ret.append('\\Draft')
        if self.get_recent:
            ret.append('\\Recent')
        return ret

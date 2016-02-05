
import datetime

import wayround_org.utils.types


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


def check_to_errors_structure(data):
    """
    return: True - ok, else - error
    """

    ret = True

    error = False

    if not error:
        if not wayround_org.utils.types.struct_check(
                data,
                TO_ERRORS_STRUCTURE
                ):
            error = True

    if not error:
        for i in data.values():
            if i['result'] not in ['error', 'success']:
                error = True
                break

    ret = not error

    return ret


class FlagMethods:

    def __init__(self):
        self.flagged = None
        self.path = None
        return

    def init_data(self):
        with self.flagged.open_flag('data', 'wb'):
            pass
        return

    def append_data(self, data):
        if self.flagged.get_is_flag_locked('data'):
            # TODO: use utils.threading.CallQueue here
            raise Exception("append_data: object already locked. TODO")
        with self.flagged.get_flag_lock('data'):
            with self.flagged.open_flag('data', 'ab') as f:
                f.write(data)
        return

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

    def get_data_lines_indexes(self, index=None, count=None):
        return self.flagged.get_int_list('data-lines')[index:count]

    def get_data_lines_index(self, index):
        return self.get_data_lines_indexes(index)

    def set_data_lines_indexes(self, value):
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
        '''
        lcount = self.get_data_lines_count()
        if index < 0:
            index = lcount+index
        '''
        return self.get_data_lines(index, None)

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

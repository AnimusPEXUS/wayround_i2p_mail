
import os
import threading
import time
import re

import yaml

import wayround_org.utils.path
import wayround_org.utils.log
import wayround_org.utils.flagged_file
import wayround_org.utils.time
import wayround_org.utils.threading


MESSAGE_META_FIELDS = [
    'title',
    'name',
    'creation_date',
    'seen?',
    'sha512'
    ]

DOMAINS_DIR_NAME = 'domains'
USERS_DIR_NAME = 'users'
LOGS_DIR_NAME = 'logs'
SPOOL_DIR_NAME = 'spool'

USER_NAME_RE = r'^[a-zA-Z][a-zA-Z0-9]*$'
USER_NAME_RE_C = re.compile(USER_NAME_RE)


def verify_mail_element_name(element_name):

    if not isinstance(element_name, str):
        raise TypeError("mail element name must be str")

    if not re.match(
            wayround_org.utils.time.TIMESTAMP_RE_PATTERN,
            element_name
            ):
        raise ValueError(
            "mail element name must be a string of 21 digit dec number"
            )
    return


def verify_user_name(name):
    if not isinstance(name, str):
        raise TypeError("user name must be str")
    if not USER_NAME_RE_C.match(name):
        raise ValueError("invalid user name")
    return


class RootDirectory:

    def __init__(self, path):
        self.path = wayround_org.utils.path.abspath(path)
        self.domains_path = wayround_org.utils.path.join(
            self.path,
            DOMAINS_DIR_NAME
            )
        self.logs_path = wayround_org.utils.path.join(
            self.path,
            LOGS_DIR_NAME
            )

        self.object_locker = wayround_org.utils.threading.ObjectLocker()
        return

    def create_normal_logger(self):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'normal'
            )

    def create_session_logger(self, timestamp):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'session',
            timestamp=timestamp
            )

    def create_error_logger(self):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'error'
            )

    def get_domain_list(self):
        ret = []

        if os.path.isdir(self.domains_path):
            for i in os.listdir(self.domains_path):
                if os.path.isdir(
                        wayround_org.utils.path.join(self.domains_path, i)
                        ):
                    ret.append(i)

        return ret

    def get_config(self):
        file_name = wayround_org.utils.path.join(self.path, 'config.yaml')

        with self.object_locker(file_name):
            with open(file_name) as f:
                ret = yaml.load(f.read())

        return ret

    def get_domain(self, domain):
        return Domain(self, domain)

    def get_is_domain_exists(self, domain):
        return os.path.isdir(
            wayround_org.utils.path.join(
                self.path,
                domain
                )
            )

    def __get__(self, domain):
        return self.get_domain(domain)

    def __in__(self, domain):
        return self.get_is_domain_exists(domain)


class SpoolDirectory:

    def __init__(self, root_dir_obj):

        if not isinstance(root_dir_obj, RootDirectory):
            raise TypeError("`root_dir_obj' must be inst of RootDirectory")

        self.root_dir_obj = root_dir_obj
        self.path = self.gen_path()
        self.object_locker = self.root_dir_obj.object_locker
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.root_dir_obj.path,
            SPOOL_DIR_NAME
            )

    def get_list(self):

        ret = []

        res = os.listdir(self.path)

        for i in res:

            if i.endswith('.data'):

                if os.path.isfile(wayround_org.utils.path.join(self.path, i)):
                    ret.append(i[:-5])

        return ret

    def new_element(self):
        ret = SpoolElement(
            self,
            wayround_org.utils.time.currenttime_stamp2_utc()
            )
        return ret


class SpoolElement:

    def __init__(self, spool_dir_obj, element_name):

        if not isinstance(spool_dir_obj, SpoolDirectory):
            raise TypeError("`spool_dir_obj' must be inst of SpoolDirectory")

        verify_mail_element_name(element_name)

        self._spool_dir_obj = spool_dir_obj
        self.object_locker = self._spool_dir_obj.object_locker
        self._element_name = element_name

        self.flagged = wayround_org.utils.flagged_file.FlaggedFile(
            self._spool_dir_obj.path,
            self._element_name,
            ['data', 'repts', 'repted'],
            object_locker=self.object_locker
            )

        self.path = self.gen_path()

        return

    @property
    def element_name(self):
        return self._element_name

    def gen_path(self):
        return self.flagged.get_flag_path('data')

    def get_is_exists(self):
        return os.path.isfile(self.path)

    def lock(self):
        self.object_locker.get_lock(self.path).acquire()
        return

    def unlock(self):
        self.object_locker.get_lock(self.path).release()
        return

    def get_is_locked(self):
        return self.object_locker.get_is_locked(self.path)

    def add_rept(self, value):
        data = self.get_repts()
        data.append(value)
        data = list(set(data))
        self.flagged.set_flag_data('repts', data)
        return

    def get_repts(self):
        return self.flagged.get_flag_data('repts')

    def add_repted(self, value):
        data = self.get_repteds()
        data.append(value)
        data = list(set(data))
        self.flagged.set_flag_data('repted', data)
        return

    def get_repteds(self):
        return self.flagged.get_flag_data('repted')

    def init_data(self):
        with open(self.path, 'wb'):
            pass
        return

    def append_data(self, data):
        with open(self.path, 'ab') as f:
            f.write(data)
        return

    def get_data_size(self):
        return

    def get_data_part(self, index, size):
        with open(self.path, 'rb') as f:
            f.seek(index)
            ret = f.read(size)
        return ret


class Domain:

    def __init__(self, root_dir_obj, domain):

        if not isinstance(root_dir_obj, RootDirectory):
            raise TypeError("`root_dir_obj' must be inst of RootDirectory")

        self.root_dir_obj = root_dir_obj
        self.object_locker = self.root_dir_obj.object_locker
        self.domain = domain
        self.path = self.gen_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.root_dir_obj.path,
            DOMAINS_DIR_NAME,
            self.domain
            )

    get_config = RootDirectory.get_config

    def get_user_list(self):
        ret = []

        lst = sorted(os.listdir(self.path))

        for i in lst:
            j = wayround_org.utils.path.join(self.path, i)
            if os.path.isdir(j):
                ret.append(i)

        return ret

    def get_enabled_user_list(self, invert=False):
        ret = []
        users = self.get_user_list()

        for i in users:
            user = self.get_user(i)
            res = user.get_enabled()
            if invert:
                res = not res
            if res:
                ret.append(i)

        return ret

    def get_disabled_user_list(self):
        return self.get_enabled_user_list(invert=True)

    def get_user(self, name):
        return User(self._root_dir_obj, self, name)

    def get_is_user_exists(self, name):
        return os.path.isdir(
            wayround_org.utils.path.join(
                self.path,
                USERS_DIR_NAME,
                name
                )
            )

    def __get__(self, name):
        return self.get_user(name)


class User:

    def __init__(self, domain_obj, name):

        if not isinstance(domain_obj, Domain):
            raise TypeError("`domain_obj' must be inst of Domain")

        verify_user_name(name)

        name = name.lower()

        self.domain_obj = domain_obj
        self.object_locker = self.domain_obj.object_locker
        self.name = name
        self.path = self.gen_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.domain_obj.path,
            USERS_DIR_NAME,
            self.name
            )

    get_config = RootDirectory.get_config

    def get_maildir_root(self):
        return MailDirRoot(self)

    def make_path(self):
        os.makedirs(self.path, exist_ok=True)
        return

    def get_exists(self):
        return self.os.path.isdir(self.path)

    def get_enabled(self):
        cfg = self.get_config()
        return not cfg['disabled']

    def get_password_data(self):
        cfg = self.get_config()
        return cfg['password']


class MailDirRoot:

    def __init__(self, user_obj):
        self.user_obj = user_obj
        self.path = self.gen_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.user_obj.path,
            'Maildir'
            )

    def get_dir(self, path):
        return MailDir(self.user_obj, path)


class MailDir:

    def __init__(self, maildir_root_obj, subpath):
        self.maildir_root_obj = maildir_root_obj
        self.object_locker = self.maildir_root_obj.object_locker
        self.subpath = subpath
        self.path = self.gen_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.maildir_root_obj.path,
            self.subpath
            )

    def listdir(self):
        return os.listdir(self.path)

    def list_dirs(self):
        ret = []
        for i in os.listdir(self.path):
            if os.path.isdir(wayround_org.utils.path.join(self.path, i)):
                ret.append(i)
        return ret

    def list_files(self):
        ret = []
        for i in os.listdir(self.path):
            if os.path.isfile(wayround_org.utils.path.join(self.path, i)):
                ret.append(i)
        return ret

    def list_messages(self):
        ret = []
        for i in os.listdir(self.path):
            if (os.path.isfile(wayround_org.utils.path.join(self.path, i))
                    and i.endswith('.data')):
                ret.append(i)
        return ret

    def get_message(self, name):
        return Message(self, name)


class Message:

    def __init__(
            self,
            maildir_obj,
            name
            ):

        verify_mail_element_name(name)

        if not isinstance(maildir_obj, MailDirectory):
            raise TypeError(
                "`maildir_obj' must be inst of MailDirectory"
                )

        self._maildir_obj = maildir_obj
        self.object_locker = self.object_locker
        self._name = name

        if name.endswith('.data'):
            raise ValueError("`name' must not end with '.data'")

        self.path = self.gen_path()

        self.flagged = wayround_org.utils.flagged_file.FlaggedFile(
            self.path,
            self.name,
            ['data', 'meta', 'lock',
             'seen', 'answered', 'flagged',
             'deleted', 'draft', 'recent']
            )

        # self.flagged.install_methods(self)

        return

    @property
    def name(self):
        return self._name

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

    def get_is_exists(self):
        return os.path.isfile(self.path)

    def get_is_locked(self):
        return self.flagged.get_is_flag_set('lock')

    def get_is_seen(self):
        return

    def lock(self)
        self.flagged.set_flag('lock')
        return

    def unlock(self):
        self.flagged.unset_flag('lock')
        return

    def wait_for_unlock(self, stop_event):
        if not isinstance(stop_event, threading.Event):
            raise TypeError("`stop_event' must be of type threading.Event")

        while True:
            if stop_event.is_set():
                break

            if not self.get_is_locked():
                break

            time.sleep(0.2)

        return

    def get_attachments(self):
        return MessageAttachments(self)

    def get_meta(self):
        with open(self.flagged.meta_path) as f:
            ret = yaml.load(f.read())
        return ret

    def set_meta(self, data):
        with open(self.flagged.meta_path, 'w') as f:
            f.write(yaml.dump(data))
        return

    def gen_meta(self):
        """
        generates .meta file for named message
        """
        data = collection.OrderedDict([
            ('title', ''),
            ('name', self.name),
            ('creation_date', None),
            ('seen?', ''),
            ('sha512', ''),
            # ('', ),
            # ('attachments', ),
            ])
        self.set_meta(data)
        return ret


def check_message_meta_field_name(value):
    if not value in MESSAGE_META_FIELDS:
        raise ValueError("invalid value for `name'")
    return


class MessageMeta:

    def __init__(self, message_obj):
        self.message_obj = message_obj
        return

    def set(self, name, value):
        check_message_meta_field_name(name)
        return

    def get(self, name):
        check_message_meta_field_name(name)
        return


class MessageAttachments:

    # TODO:  objects of this type must be list-alike for easy usage

    def __init__(self, message_obj, meta_data):
        self.message_obj = message_obj

        self.data = data['attachments']

        if not verify_attachments_data(self.data):
            raise ValueError(
                "invalid meta_data passed for MessageAttachments"
                )

        return

    def __len__(self):
        return


def verify_data(data):
    """
    True - Ok, False - Error
    """
    return True


class MessageAttachment:

    def __init__(self, message_attachments_obj, size, mime_type, data):
        self.message_attachments_obj = message_attachments_obj
        return

    def get_size(self):
        return

    def get_mime_type(self):
        return

    def get_data(self, index, size):
        return


import os
import threading
import time

import yaml

import wayround_org.utils.path
import wayround_org.utils.log


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


class Domain:

    def __init__(self, root_dir_obj, domain):
        self.root_dir_obj = root_dir_obj
        self.domain = domain
        self.path = self.gen_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.root_dir_obj.path,
            DOMAINS_DIR_NAME,
            self.domain
            )

    def get_user_list(self):
        return

    def get_enabled_user_list(self):
        return

    def get_disabled_user_list(self):
        return

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
        self.domain_obj = domain_obj
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

    def __init__(self, maildir_obj, name):
        self.maildir_obj = maildir_obj
        self.name = name

        if name.endswith('.data'):
            raise ValueError("`name' must not end with '.data'")

        self.path = self.gen_path()
        self.meta_path = self.gen_meta_path()
        self.lock_path = self.gen_lock_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.maildir_obj.path,
            self.name
            ) + '.data'

    def gen_meta_path(self):
        return wayround_org.utils.path.join(
            self.maildir_obj.path,
            self.name
            ) + '.meta'

    def gen_lock_path(self):
        return wayround_org.utils.path.join(
            self.maildir_obj.path,
            self.name
            ) + '.lock'

    def is_exists(self):
        return os.path.isfile(self.path)

    def is_locked(self):
        return os.path.isfile(self.lock_path)

    def lock(self):
        with open(self.lock_path, 'w'):
            pass
        return

    def unlock(self):
        if os.path.isfile(self.lock_path):
            os.unlink(self.lock_path)
        return

    def wait_for_unlock(self, stop_flag):
        if not isinstance(stop_flag, threading.Event):
            raise TypeError("`stop_flag' must be of type threading.Event")

        while True:
            if stop_flag.is_set():
                break

            if not self.is_locked():
                break

            time.sleep(0.2)

        return

    def get_attachments(self):
        return MessageAttachments(self)

    def get_meta(self):
        with open(self.meta_path) as f:
            ret = yaml.load(f.read())
        return ret

    def set_meta(self, data):
        with open(self.meta_path, 'w') as f:
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

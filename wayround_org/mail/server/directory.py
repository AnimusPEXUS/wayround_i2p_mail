
import os
import threading
import time
import re
import collections

import yaml

import wayround_org.utils.path
import wayround_org.utils.log
import wayround_org.utils.flagged_file
import wayround_org.utils.time
import wayround_org.utils.threading

'''

NAMING CONVENTIONS:

    NOTE: this module consideres terms [user 'registered'] and [user 'exists']
          as synonims: exists == registered; [not registered] == [not exists].

          And 'exists' name used in all callable names and values linked to
          User class.

SPOOL DIRECTORY DEDICATION:

    Spool directory is the placement for messages which arriving from smtp
    clients.

    Spool directory implimentation in this module aims to be only mechanical.
    It's does not do any right management or accepptance allowance for
    registered or unregistered users. so spool directory can be used in both
    finall mail accepting server or in mail relay system.

    -----------------------
    case 1 of 2: Finall MTA
    -----------------------

    MTA SMTP server should do only minimal checks before deciding to pass
    message into spool:

        1. Mail from unregistered user can be accepted into spool only if
           it's destination available locally. Else message should not be
           passed into spool and SMTP client shoul be informed about access
           restriction.

        2. Mail comming from registered (and enabled) user, can be passed into
           spool and relayed into any direction: into local or into remote
           destination.

    Described above checks should be done by spool working process too
    (which, probably, is the relay mechanism too). So Yes, probably this is
    a double work.

    -------------------------
    case 2 of 2: Relaying MTA
    -------------------------

    In this case, server does not have local storage, and it's only mission is
    to pass message to destination or to other relay.

    ---

    /-------------------------\
    | registered SMTP session |
    \-------------------------/
       |
       V                      /----------------\
    /------------------\ ---> | local delivery |
    | Spool Directory  |      \----------------/
    \------------------/         /-----------------\
       ^          \------------> | remote delivery |
       |                         \-----------------/
    /---------------------------\
    | unregistered SMTP session |
    \---------------------------/
'''


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
        self._spool_directory = SpoolDirectory(self)
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

    def make_path(self):
        os.makedirs(self.path, exist_ok=True)
        return

    def get_config(self):
        ret = {}

        file_name = wayround_org.utils.path.join(self.path, 'config.yaml')

        if os.path.isfile(file_name):
            with self.object_locker.get_lock(file_name):
                with open(file_name) as f:
                    ret = yaml.load(f.read())

        return ret

    def set_config(self, data):
        """
        result: True - ok, False - error
        """

        ret = False

        file_name = wayround_org.utils.path.join(self.path, 'config.yaml')

        if not self.get_is_exists():
            ret = False
        else:
            with self.object_locker.get_lock(file_name):
                with open(file_name) as f:
                    f.write(yaml.dump())

        return ret

    def get_is_exists(self):
        return os.path.isdir(self.path)

    def get_domain_list(self):
        ret = []

        if os.path.isdir(self.domains_path):
            for i in os.listdir(self.domains_path):
                if os.path.isdir(
                        wayround_org.utils.path.join(self.domains_path, i)
                        ):
                    ret.append(i)

        return ret

    def get_enabled_domain_list(self, invert=False):
        ret = []
        domains = self.get_domain_list()

        for i in domains:
            doamin = self.get_domain(i)
            res = doamin.get_enabled()
            if invert:
                res = not res
            if res:
                ret.append(i)

        return ret

    def get_disabled_domain_list(self):
        return self.get_enabled_domain_list(invert=True)

    def get_spool_directory(self):
        return self._spool_directory

    def get_domain(self, domain):
        return Domain(self, domain)

    def get_user(self, domain, user):
        domain_obj = self.get_domain(domain)
        ret = domain_obj.get_user(user)
        return ret

    def get_is_domain_exists(self, domain):
        domain_obj = self.get_domain(domain)
        ret = domain_obj.get_is_exists()
        return ret

    def get_is_user_exists(self, domain, user):
        domain_obj = self.get_domain(domain)
        user_obj = domain_obj.get_user(user)
        ret = user_obj.get_is_exists(user)
        return ret

    def get_is_user_enabled(self, domain, user):
        domain_obj = self.get_domain(domain)
        user_obj = domain_obj.get_user(user)
        ret = user_obj.get_is_enabled()
        return ret

    def __get__(self, domain):
        return self.get_domain(domain)

    def __in__(self, domain):
        return self.get_is_domain_exists(domain)


class Domain:

    def __init__(self, root_dir_obj, domain):

        if not isinstance(root_dir_obj, RootDirectory):
            raise TypeError("`root_dir_obj' must be inst of RootDirectory")

        domain = domain.lower()

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

    make_path = RootDirectory.make_path

    get_config = RootDirectory.get_config
    set_config = RootDirectory.set_config

    def get_is_exists(self):
        ret = False
        has_dir = os.path.isdir(self.path)

        config = self.get_config()

        has_config = config is not None

        enabled_in_config = 'enabled' in config

        ret = has_dir and has_config and enabled_in_config
        return ret

    def get_is_enabled(self):
        cfg = self.get_config()
        ret = bool(cfg['enabled'])
        return ret

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

    def __get__(self, name):
        return self.get_user(name)

    def __in__(self, name):
        return self.get_user(name).get_is_exists()


class User:
    """
    Representaition of user data on mailserver directory tree

    This manages password data and availability state of user in system.

    The user is considered registered in system if:
        1. it has existing directory;
        2. with config;
        3. in which 'enabled' field is present.
        If all those 3 things True - user is registered, but not yet enabled!

    User is considered enabled only if it is registered and it's config
    'enabled' value is True. In any other cases user is considered disabled.

    This class MUST NOT do any modifications to file system (and particularly
    to user directory (including it's creation)) on 'read'-type functions. So
    directory shoul not be created if someone tries to get information on user
    existance (registration) and also user must bot be created if someone
    tries to set it's password.

    NOTE: read NAMING CONVENTIONS on top of this file.
    """

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
    set_config = RootDirectory.set_config

    get_is_exists = Domain.get_is_exists
    get_is_enabled = Domain.get_is_enabled

    make_path = RootDirectory.make_path

    def get_maildir_root(self):
        return MailDirRoot(self)

    def get_password_data(self):
        cfg = self.get_config()
        return cfg['password']

    def set_password_data(self, data):
        # if not isinstance(data, bytes):
        #    raise TypeError("")
        cfg = self.get_config()
        cfg['password'] = data
        self.set_config(cfg)
        return


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

    def get_dir_list(self):
        ret = []
        for i in self.listdir():
            if os.path.isdir(wayround_org.utils.path.join(self.path, i)):
                ret.append(i)
        return ret

    def get_file_list(self):
        ret = []
        for i in self.listdir():
            if os.path.isfile(wayround_org.utils.path.join(self.path, i)):
                ret.append(i)
        return ret

    def get_message_list(self):
        ret = self.get_file_list()

        for i in range(len(ret) - 1, -1, -1):
            if not ret[i].endswith('.data'):
                del ret[i]
            else:
                ret[i] = ret[i][:-5]

        return ret

    def get_message(self, name):
        return Message(self, name)


class Message:

    def __init__(self, maildir_obj, name):

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
            [
                # message it self. as sent by client. no any changes.
                # untouchable
                'data',

                # list of dicts with attachment(s) data
                'attachments',

                # dict. empty if not seen yet. if seen - has key 'seen' with
                # iso data when was seen
                'seen',

                # TODO
                'answered',

                # TODO
                'flagged',

                # flagged for deletion
                'deleted',

                # flagged as draft
                'draft',

                # TODO
                'recent'
                ]
            )

        # self.flagged.install_methods(self)

        self.attachments = MessageAttachments(self)

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
        data = collections.OrderedDict([
            ('title', ''),
            ('name', self.name),
            ('creation_date', None),
            ('seen?', ''),
            ('sha512', ''),
            # ('', ),
            # ('attachments', ),
            ])
        self.set_meta(data)
        return

    def get_attachments(self):
        return self.message_obj.flagged.get_flag_data('attachments')

    def set_attachments(self, data):
        return self.message_obj.flagged.set_flag_data('attachments', data)


def check_message_meta_field_name(value):
    if not value in MESSAGE_META_FIELDS:
        raise ValueError("invalid value for `name'")
    return


def verify_data(data):
    """
    True - Ok, False - Error
    """
    # TODO
    return True


def verify_attachments_data(data):
    """
    True - Ok, False - Error
    """
    # TODO
    return True


class MessageAttachment:

    @classmethod
    def new_from_dict(cls, data_dict):
        ret = cls(
            data_dict['size'],
            data_dict['mime_type'],

            )
        return ret

    def __init__(self, size, mime_type, data):
        self.message_attachments_obj = message_attachments_obj
        return

    def gen_dict(self):
        return ret

    def get_size(self):
        return

    def get_mime_type(self):
        return

    def get_data(self, index, size):
        return


class SpoolDirectory:
    """

    Spool directory - is the place where SMTP incomming messages are placed
    before being transported to next destination

    see ascii scheme on file top
    """

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

    make_path = RootDirectory.make_path

    def listdir(self):
        return os.listdir(self.path)

    listdir = MailDir.listdir
    get_file_list = MailDir.get_file_list
    get_element_list = MailDir.get_message_list

    def new_element(self):
        ret = SpoolElement(
            self,
            wayround_org.utils.time.currenttime_stamp_utc()
            )
        return ret

    def get_element(self, name):
        return SpoolElement(self, name)


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
            [
                # unmodified recived message
                'data',

                # list of dicts: {'name': str, 'address': str}
                'to',

                # like 'to'
                'from',

                # only flag. exists(set) if incomming smtp session is finished
                # ok
                'in_finished'

                # only flag. exists(set) if internal procedures finished trying
                # send mail to destination
                'out_finished',

                # list of destinations, which recived message without errors
                'out_ok'

                # dict of destinations, which recived message with errors.
                # values are dicts with 'code' (int) and 'message' (str)
                # as error message
                'out_error'
                ],
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
        if not self.object_locker.get_is_locked(self.path):
            raise Exception("append_data: object already locked. TODO")
        with self.object_locker.get_lock(self.path):
            with open(self.path, 'ab') as f:
                f.write(data)
        return

    def get_data_size(self):
        return os.stat(self.path).st_size

    def get_data_part(self, index=None, size=None):
        with self.object_locker.get_lock(self.path):
            with open(self.path, 'rb') as f:
                if index is not None:
                    f.seek(index)
                ret = f.read(size)
        return ret

    def get_in_finished(self):
        return self.flagged.get_is_flag_set('in_finished')

    def set_in_finished(self, value=True):
        if value:
            self.flagged.set_flag('in_finished')
        else:
            self.flagged.unset_flag('in_finished')
        return

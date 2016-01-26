
import os
import threading
import time
import re
import collections
import weakref
import threading

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

        self._get_domain_dict = weakref.WeakValueDictionary()
        self._get_domain_lock = threading.Lock()

        return

    def create_normal_logger(self, group=None, user=None):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'normal',
            group=group,
            user=user
            )

    def create_session_logger(self, timestamp, group=None, user=None):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'session',
            timestamp=timestamp,
            group=group,
            user=user
            )

    def create_error_logger(self, group=None, user=None):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'error',
            group=group,
            user=user
            )

    def makedirs(self):
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

        with self.object_locker.get_lock(file_name):
            with open(file_name, 'w') as f:
                f.write(yaml.dump(data))

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

        with self._get_domain_lock:

            if domain not in self._get_domain_dict:
                _t = Domain(self, domain)
                self._get_domain_dict[domain] = _t

            ret = self._get_domain_dict[domain]

        return ret

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
        ret = user_obj.get_is_exists()
        return ret

    def get_is_user_enabled(self, domain, user):
        domain_obj = self.get_domain(domain)
        user_obj = domain_obj.get_user(user)
        ret = user_obj.get_is_enabled()
        return ret

    def __getitem__(self, domain):
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
        self.users_path = wayround_org.utils.path.join(
            self.path,
            USERS_DIR_NAME
            )

        self._get_user_dict = weakref.WeakValueDictionary()
        self._get_user_lock = threading.Lock()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.root_dir_obj.path,
            DOMAINS_DIR_NAME,
            str(self.domain.encode('idna'), 'utf-8')
            )

    makedirs = RootDirectory.makedirs

    get_config = RootDirectory.get_config
    set_config = RootDirectory.set_config

    def create(self):
        self.makedirs()
        self.set_is_enabled(self.get_is_enabled())
        return

    def get_is_exists(self):
        ret = False
        has_dir = os.path.isdir(self.path)

        config = self.get_config()

        has_config = False
        enabled_in_config = False

        if isinstance(config, dict):
            has_config = True
            enabled_in_config = 'enabled' in config

        ret = has_dir and has_config and enabled_in_config

        return ret

    def get_is_enabled(self):
        cfg = self.get_config()
        ret = (
            isinstance(cfg, dict)
            and 'enabled' in cfg
            and cfg['enabled'] == True
            )
        return ret

    def set_is_enabled(self, value):
        if not isinstance(value, bool):
            raise TypeError("is_enabled value must be bool")
        cfg = self.get_config()
        cfg['enabled'] = value
        self.set_config(cfg)
        return

    def get_user_list(self):
        ret = []

        lst = sorted(os.listdir(self.users_path))

        for i in lst:
            j = wayround_org.utils.path.join(self.users_path, i)
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
        with self._get_user_lock:

            if name not in self._get_user_dict:
                _t = User(self, name)
                self._get_user_dict[name] = _t

            ret = self._get_user_dict[name]

        return ret

    def __getitem__(self, name):
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
            str(self.name.encode('idna'), 'utf-8')
            )

    get_config = RootDirectory.get_config
    set_config = RootDirectory.set_config

    create = Domain.create

    def get_is_exists(self):
        """

        This does not takes into account result of get_is_exists() of parent
        Domain instance. use get_is_user_exists() method of RootDirectory class
        inst for taking Domain settings into account.
        """
        return Domain.get_is_exists(self)

    def get_is_enabled(self):
        """
        This does not takes into account result of get_is_enabled() of parent
        Domain instance. use get_is_user_enabled() method of RootDirectory
        class inst for taking Domain settings into account.
        """
        return Domain.get_is_enabled(self)

    set_is_enabled = Domain.set_is_enabled

    makedirs = RootDirectory.makedirs

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
        return sorted(os.listdir(self.path))

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
        lst = self.get_file_list()

        ret = []

        for i in lst:
            ji = wayround_org.utils.path.join(self.path, i)
            if os.file.isfile(ji):
                point_pos = i.rfind('.')
                if point_pos != -1:
                    i_name = i[:point_pos]
                    if not i_name in ret:
                        ret.append(i_name)

        return ret

    def get_message(self, name):
        return Message(self, name)


class Message:

    def __init__(self, maildir_obj, name):

        verify_mail_element_name(name)

        if not isinstance(maildir_obj, MailDir):
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

        # self.attachments = MessageAttachments(self)

        return

    def gen_path(self):
        return self.flagged.get_flag_path('data')

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
        return self.flagged.get_flag_data('attachments')

    def set_attachments(self, data):
        return self.flagged.set_flag_data('attachments', data)


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

    '''
    @classmethod
    def new_from_dict(cls, data_dict):
        ret = cls(
            data_dict['size'],
            data_dict['mime_type'],

            )
        return ret
    '''

    def __init__(self, size, mime_type, data):
        return

    def gen_dict(self):
        return

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

    makedirs = RootDirectory.makedirs

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

    # WARNING!: do not make Message class a child of SpoolElement
    #           class and do not copy spool elements into users'
    #           folders 'as is' in spool to avoid disclosure of
    #           confidential fields in 'to' list and like it.

    def __init__(self, spool_dir_obj, element_name):

        if not isinstance(spool_dir_obj, SpoolDirectory):
            raise TypeError("`spool_dir_obj' must be inst of SpoolDirectory")

        verify_mail_element_name(element_name)

        self._spool_dir_obj = spool_dir_obj
        self.object_locker = self._spool_dir_obj.object_locker
        self.lock = None
        self._element_name = element_name

        self.flagged = wayround_org.utils.flagged_file.FlaggedFile(
            self._spool_dir_obj.path,
            self._element_name,
            [
                # ===========================================================
                # subject flags
                # -----------------------------------------------------------

                # unmodified recived message
                'data',
                # message size proposed by client
                'size',
                # existing and enabled user under which client authenticated
                # on submission
                'auth_as',

                # ===========================================================
                # "from" flags
                # (flags and indicators concerning incomming messages)
                # -----------------------------------------------------------

                # str (email addresse)
                'from',

                # bool
                #
                # True: indicates what incomming mail accepted with no errors,
                #       i.e.:
                #   - connection was not interrupted
                #   - message transfer ended with <CRLF>.<CRLF>
                #   - etc.
                #
                # False: message reciving was interrupted before <CRLF>.<CRLF>
                'input_data_finished',

                # bool
                #
                # 'input_data_finished' + QUIT command processed successfuly
                'quit_ok',

                # ===========================================================
                # "to" flags
                # (flags and indicators concerning incomming messages)
                # -----------------------------------------------------------

                # set of str (email addresses)
                'to',

                # only flag.
                #
                # considered to be True if is set (file exists) and has value
                # of True.
                #
                # Indicates what spool processing threads finished doing any
                # actions to this message and it's free to be removed from
                # spool. This includes all/any tries to send messages to
                # recipients
                'to_finished',

                # set of str (email addresses)
                #
                # Addresses not which not attempt to send (transport).
                # can be set by submission accepting thread or by
                # transportation thread in case of exhuasted tries to transport
                # mail to destination.
                'to_disabled',

                # list of destinations, which recived message without errors
                'to_success',

                # dict of destinations, which received (or not received)
                # message with errors.
                # values are dicts with 'code' (int) and 'message' (str)
                # as error message
                'to_errors',

                ],
            ['data'],  # flags to which YAML assess is invalid
            object_locker=self.object_locker
            )

        self.path = self.gen_path()

        return

    '''
    @property
    def element_name(self):
        return self._element_name
    '''

    def gen_path(self):
        return self.flagged.get_flag_path('data')

    def get_is_exists(self):
        return os.path.isfile(self.path)

    def acquire(self):
        self.object_locker.get_lock(self.path).acquire()
        return

    def release(self):
        self.object_locker.get_lock(self.path).release()
        return

    def get_is_locked(self):
        return self.object_locker.get_is_locked(self.path)

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

    def get_real_size(self):
        return os.stat(self.path).st_size

    def set_size(self, value):
        if value is not None and not isinstance(value, int):
            raise TypeError("`size' must be int")
        self.flagged.set_flag_data('size', value)
        return

    def get_size(self):
        ret = self.flagged.get_flag_data('size')
        if len(list(ret.keys())) == 0:
            ret = None
        return ret

    def get_auth_as(self):
        return self.flagged.get_flag_data('auth_as')

    def set_auth_as(self, value):
        if value is not None and not isinstance(value, str):
            raise TypeError("`auth_as' must be None or str")
        self.flagged.set_flag_data('auth_as', value)
        return

    def get_from(self):
        return self.flagged.get_str('from')

    def set_from(self, value):
        # TODO: structure check
        self.flagged.set_str('from', value)
        return

    def get_input_data_finished(self):
        return self.flagged.get_bool('input_data_finished')

    def set_input_data_finished(self, value=True):
        self.flagged.set_bool('input_data_finished', value)
        return

    def get_quit_ok(self):
        return self.flagged.get_bool('quit_ok')

    def set_quit_ok(self, value=True):
        self.flagged.set_bool('quit_ok', value)
        return

    def get_to(self):
        ret = self.flagged.get_flag_data('to')
        if not isinstance(ret, list):
            ret = []
        return ret

    def set_to(self, value):
        # TODO: structure check
        self.flagged.set_flag_data('to', value)
        return

    def add_to(self, value):
        self.set_to(self.get_to() + [value])
        return

    def get_to_finished(self):
        return self.flagged.get_bool('to_finished')

    def set_to_finished(self, value=True):
        self.flagged.set_bool('to_finished', value)
        return

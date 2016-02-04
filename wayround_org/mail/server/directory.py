
import collections
import datetime
import glob
import os
import re
import shutil
import threading
import time
import weakref

import yaml

import wayround_org.utils.flagged_file
import wayround_org.utils.log
import wayround_org.utils.path
import wayround_org.utils.threading
import wayround_org.utils.time


DOMAINS_DIR_NAME = 'domains'
USERS_DIR_NAME = 'users'
MAIL_DIR_NAME = 'maildir'
LOGS_DIR_NAME = 'logs'
SPOOL_DIR_NAME = 'spool'

USER_NAME_RE = r'^[a-zA-Z][a-zA-Z0-9]*$'
USER_NAME_RE_C = re.compile(USER_NAME_RE)


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

    def create_session_logger(self, name, timestamp, group=None, user=None):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'session-{}'.format(name),
            # timestamp=timestamp,
            group=group,
            user=user
            )

    def create_spool_logger(self, name):
        return wayround_org.utils.log.Log(
            self.logs_path,
            'spool-{}'.format(name)
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
                i_lower = i.lower()  # only lower case domain names are valid
                j = wayround_org.utils.path.join(self.domains_path, i_lower)
                if os.path.isdir(j):
                    ret.append(i_lower)

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
            i_lower = i.lower()  # only lower case domain names are valid
            j = wayround_org.utils.path.join(self.users_path, i_lower)
            if os.path.isdir(j):
                ret.append(i_lower)

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

        if not isinstance(user_obj, User):
            raise TypeError("`user_obj' must be inst of User")

        self.user_obj = user_obj
        self.path = self.gen_path()
        return

    def gen_path(self):
        return wayround_org.utils.path.join(
            self.user_obj.path,
            MAIL_DIR_NAME
            )

    makedirs = RootDirectory.makedirs

    def get_dir(self, path):
        return MailDir(self, path)


class MailDir:

    def __init__(self, maildir_root_obj, subpath):

        if not isinstance(maildir_root_obj, MailDirRoot):
            raise TypeError("`maildir_root_obj' must be inst of MailDirRoot")

        self.maildir_root_obj = maildir_root_obj
        self.object_locker = self.maildir_root_obj.user_obj.object_locker
        self.subpath = subpath.strip().strip('/')
        print(
            "Creating Maildir for subpath: '{}', '{}'".format(
                self.subpath,
                subpath
                )
            )

        self.path = self.gen_path()

        j = wayround_org.utils.path.join(
            self.maildir_root_obj.path,
            self.subpath
            )

        if not wayround_org.utils.path.is_subpath_real(
                j,
                self.maildir_root_obj.path
                ):
            raise Exception("invalid path requested")
        print(
            "    resulting path: '{}'".format(
                self.path
                )
            )

        return

    makedirs = RootDirectory.makedirs

    def gen_path(self):

        if self.subpath == '':
            ret = self.maildir_root_obj.path
        else:
            ret = wayround_org.utils.path.join(
                self.maildir_root_obj.path,
                self.subpath
                )

        return ret

    def create(self):
        """
        return: True - ok, else - error
        """
        self.makedirs()
        return os.path.isdir(self.path)

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

    def get_directory(self, subpath):
        j = wayround_org.utils.path.join(self.subpath, subpath)
        self.maildir_root_obj.get_maildir(j)
        return

    def get_message(self, name):
        """
        Allows getting non existing messages for consecuontal creation
        """
        return Message(self, name)

    def glob(self, pathname, recursive=False):

        # TODO: security checks required

        glob_res = glob.glob(
            wayround_org.utils.path.join(self.path, pathname),
            recursive=recursive
            )

        self_path_l = len(self.path)

        for i in range(len(glob_res) - 1, -1, -1):
            glob_res[i] = glob_res[i][self_path_l + 1:]

        ret = glob_res

        return ret


class MessageFlags:

    def __init__(self, path, name):

        if not isinstance(path, str):
            raise TypeError("`path' must be str")

        verify_mail_element_name(name)

        self.flagged = wayround_org.utils.flagged_file.FlaggedFile(
            path,
            name,
            [
                # message it self. as sent by client. no any changes.
                # untouchable
                'data',

                # list of dicts with attachment(s) data
                'attachments',

                # str or None.
                #
                # None - not seen yet.
                # str - text of iso8601 format, date when seen
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


class TransitionMessage(MessageFlags):

    def __init__(self, path, name):

        verify_mail_element_name(name)

        if not isinstance(path, str):
            raise TypeError("`path' must be str")

        self._name = name

        if name.endswith('.data'):
            raise ValueError("`name' must not end with '.data'")

        self.path = path

        super().__init__(self.path, self._name)

        return

    def perform_transition(
            self,
            spool_element_obj,
            maildir_obj
            ):
        self.import_from_spool_element(spool_element_obj)
        self.gen_message(maildir_obj)
        return

    def import_from_spool_element(self, spool_element_obj):
        if not isinstance(spool_element_obj, SpoolElement):
            raise TypeError(
                "`spool_element_obj' must be inst of SpoolElement"
                )

        flags = ['data', 'size']

        '''
        flags = self.flagged.get_possible_flags_copy()
        for i in ['data']:
            if i in flags:
                flags.remove(i)
        '''

        for i in flags:
            shutil.copy2(
                spool_element_obj.flagged.get_flag_path(i),
                self.path
                )

        return

    def gen_message(self, maildir_obj):
        msg = maildir_obj.get_message(self._name)
        msg.import_from_transition(self)
        return


class Message(MessageFlags):

    def __init__(self, maildir_obj, name):

        verify_mail_element_name(name)

        if not isinstance(maildir_obj, MailDir):
            raise TypeError(
                "`maildir_obj' must be inst of MailDirectory"
                )

        self._maildir_obj = maildir_obj
        self.object_locker = self._maildir_obj.object_locker
        self._name = name

        if name.endswith('.data'):
            raise ValueError("`name' must not end with '.data'")

        self.path = self.gen_path()

        # self.attachments = MessageAttachments(self)

        super().__init__(self.path, self.name)

        return

    def gen_path(self):
        return self.flagged.get_flag_path('data')

    @property
    def name(self):
        return self._name

    def makedirs(self):
        ret = self._maildir_obj.makedirs()
        return ret

    def import_from_transition(self, transition_message_obj):
        if not isinstance(transition_message_obj, TransitionMessage):
            raise TypeError(
                "`transition_message_obj' must be inst of TransitionMessage"
                )

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

    def get_transition_message(self, name):
        return TransitionMessage(
            wayround_org.utils.path.join(
                self.path,
                'spool_conversion_tmp'
                ),
            name
            )


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

                # bool
                #
                # True: indicates what incomming mail accepted with no errors,
                #       i.e.:
                #   - connection was not interrupted
                #   - message transfer ended with <CRLF>.<CRLF>
                #   - etc.
                #
                # False: message reciving was interrupted before <CRLF>.<CRLF>
                'data-ok',

                # bool
                #
                # 'data-ok' + QUIT command processed successfuly
                'quit-ok',

                # int - message size proposed by client with 'MAIL FROM' cmd
                'size',

                # str - local email with which client managed to authenticate
                'auth-as',

                # str - single line text
                # 'Received' field string, which should be prepended to
                # message during transition operation
                'received',

                # str - email address
                # 'Return-Path' field string, which should be prepended to
                # message during transition operation
                'return-path',

                # ===========================================================
                # "from" flags
                # (flags and indicators concerning incomming messages)
                # -----------------------------------------------------------

                # str - email address passed with 'MAIL FROM' cmd
                # NOTE: in case of submission smtp service mode, this should be
                #       equal to 'return-path', else this is security error.
                'from',

                # dict with struct:
                #
                # {
                #     'remote_addr': str,  # ip and port tuple in case of IP family
                #     'local_addr': str,  # same but for local part
                #     'SSL': {  # None or dict
                #         }
                #     'datetime': datetime.datetime  # in UTC
                #     }

                # ===========================================================
                # "to" flags
                # (flags and indicators concerning incomming messages)
                # -----------------------------------------------------------

                # set of 0 or more strs (email addresses)
                'to',

                # set of str (email addresses)
                #
                # Addresses on which not attempt to send (transport).
                # can be set by submission accepting thread or by
                # transportation thread in case of exhuasted tries to transport
                # mail to destination.
                'to-disabled',

                # set of str (e-mails), which recived message without errors
                #
                # NOTE: successful transfers must be added not only here but
                #       also to to-disabled
                'to-success',

                # dict with following struct:

                # mail purpuse - mini log
                # saves not only errors, but also successes logs.
                # must contain textual responses of servers.
                #
                # example and structural concept.
                # {
                #     # zero or more records. each key - an email to which wass
                #     # made sending attempt
                #
                #     'johndoe@example.net': [
                #
                #         # zero or more dicts
                #         # spooler can use this to limit number of attempts
                #
                #         {
                #             'result': 'error',
                #             'code': integer_code_here,
                #             'message': 'Message exited maximum size limit',
                #
                #             # datetime when attempt was performed.
                #             # on this must be based spooler
                #             # sending reattempt delay
                #
                #             'datetime': value
                #             },
                #         {
                #             'result': 'error',
                #             'code': integer_code_here,
                #             'message': 'some other error',
                #             'datetime': value
                #             },
                #         {
                #             'result': 'success',
                #             'code': integer_code_here,
                #             'message': 'message from server',
                #             'datetime': value
                #             }
                #         ]
                # }
                'to-errors',

                # bool
                #
                # considered to be True if get_bool() result equals True
                #
                # Indicates what spool processing threads finished doing any
                # actions to this message and it's free to be removed from
                # spool. This includes all/any tries to send messages to
                # recipients
                'to-finished',
                ],
            ['data'],  # flags to which YAML access methods is invalid
            object_locker=self.object_locker
            )

        self.path = self.gen_path()

        self._lock = self.object_locker.get_lock(self.path)

        return

    def get_name(self):
        return self._element_name

    def gen_path(self):
        return self.flagged.get_flag_path('data')

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return

    def lock(self):
        return self._lock.acquire()

    def unlock(self):
        return self._lock.release()

    def get_is_locked(self):
        return self._lock.get_locked()

    def get_is_exists(self):
        return os.path.isfile(self.path)

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
        return ret

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

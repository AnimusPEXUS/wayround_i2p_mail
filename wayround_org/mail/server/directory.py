
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
import wayround_org.utils.pm

import wayround_org.mail.server.directory_flag_methods


DOMAINS_DIR_NAME = 'domains'
USERS_DIR_NAME = 'users'
MAIL_DIR_NAME = 'maildir'
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

        self._permanent_memory = \
            wayround_org.utils.pm.PersistentMemory.new_fs_memory(
                wayround_org.utils.path.join(
                    self.path,
                    'permanent_memory'
                    )
                )

        return

    def get_permanent_memory(self):
        return self._permanent_memory

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
            if os.path.isfile(ji):
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

    def new_message(self):
        ret = Message(
            self,
            wayround_org.utils.time.currenttime_stamp_utc()
            )
        return ret

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

    def find_set_flags(self):

        res = set()

        initial_list = [
            'seen',
            'answered',
            'flagged',
            'deleted',
            'draft',
            'recent'
            ]

        lst = self.get_message_list()

        for i in lst:
            for j in initial_list:
                if not j in res:
                    if getattr(
                            self.get_message(i),
                            'get_{}'.format(j)
                            )():
                        res.add(j)

        ret = []

        for i in res:
            ret.append('\\{}'.format(i.capitalize()))

        ret.sort()

        return ret

    def get_recent_message_list(self):
        ret = []
        lst = self.get_message_list()
        for i in lst:
            msg = self.get_message(i)
            if msg.get_recent():
                ret.append(i)
        return ret


class LockableMailElement:

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return

    def acquire(self):
        return self._lock.acquire()

    def release(self):
        return self._lock.release()

    def lock(self):
        return self._lock.acquire()

    def unlock(self):
        return self._lock.release()

    def get_is_locked(self):
        return self._lock.get_locked()

    def get_is_exists(self):
        return os.path.isfile(self.path)


class MessageIndexBuilder:
    """
    Searches and saves line indexes, line indexes of sections, subject flag
    """

    def gen_message(self, maildir_obj, log):
        msg = maildir_obj.get_message(self._name)
        msg.import_from_transition(self, log)
        return

    def import_from_spool_element(
            self,
            spool_element_obj,
            log,
            stop_event=None
            ):
        if not isinstance(spool_element_obj, SpoolElement):
            raise TypeError(
                "`spool_element_obj' must be inst of SpoolElement"
                )

        self.makedirs()

        # ------------------------------------------------------------------

        log.info("Transferring data")

        received = spool_element_obj.get_received()
        return_path = spool_element_obj.get_return_path()

        speo_file = spool_element_obj.flagged.open_flag('data', 'br')
        tmeo_file = self.flagged.open_flag('data', 'bw')

        if received is not None:
            log.info("    prepending Received field")
            tmeo_file.write(b"Received: ")
            tmeo_file.write(bytes(received, 'utf-8'))
            tmeo_file.write(wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR)

        if return_path is not None:
            log.info("    prepending Return-path field")
            tmeo_file.write(b"Return-path: ")
            tmeo_file.write(bytes(return_path, 'utf-8'))
            tmeo_file.write(wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR)

        log.info("    transferring rest of the data")

        while True:
            if stop_event is not None and stop_event.is_set():
                break

            buf = speo_file.read(2 * 1024**2)
            if len(buf) == 0:
                break

            tmeo_file.write(buf)

        speo_file.close()
        tmeo_file.close()

        del speo_file, tmeo_file, received, return_path

        log.info("    DONE: data transfer complete")

        self.reindex(stop_event, log)

        return

    def reindex(self, stop_event, log):
        # ------------------------------------------------------------------

        log.info("Calculating data lines..")
        self.calculate_data_lines_indexes(log, stop_event)
        log.info("    DONE")

        # print("get_data_lines: {}".format(self.get_data_lines()))

        # ------------------------------------------------------------------

        log.info("Determining sections..")
        self.calculate_section_lines(log, stop_event)
        log.info("    DONE")

        # ------------------------------------------------------------------

        log.info("Determining title..")
        self.calculate_subject(log, stop_event)
        log.info("    DONE")

        # ------------------------------------------------------------------

        log.info("Setting up initial message flags..")
        self.setup_initial_flags(log, stop_event)
        log.info("    DONE")

        # ------------------------------------------------------------------

        return

    def calculate_data_lines_indexes(
            self,
            log,
            stop_event,
            line_length_bytes_limit=2 * 1024**2,  # 2 MiB
            ):

        ret = 0

        input_invalid = False

        data = []

        tmeo_file = self.flagged.open_flag('data', 'br')

        offset = 0

        data.append(offset)

        buff = b''

        while True:
            if stop_event is not None and stop_event.is_set():
                break

            if len(buff) >= line_length_bytes_limit:
                input_invalid = True
                break

            tmeo_read_res = tmeo_file.read(500)

            if len(tmeo_read_res) == 0:
                # TODO: probably some input data check need to be added
                #       for instance if buffer does not ends with line
                #       seporator.
                #       Although I think this is normal ending for this
                #       loop.
                break

            buff += tmeo_read_res

            while True:

                if stop_event is not None and stop_event.is_set():
                    break

                bf_res = buff.find(
                    wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
                    )

                if bf_res == -1:
                    break

                else:
                    offset = (
                        offset +
                        bf_res +
                        wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR_LEN
                        )
                    data.append(offset)
                    buff = buff[
                        bf_res +
                        wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR_LEN:
                        ]

        if (stop_event is not None and stop_event.is_set()) or input_invalid:
            self.set_data_lines_indexes(None)
            ret = 1
        else:
            self.set_data_lines_indexes(data)

        return ret

    def _calculate_section_lines_sub_01(
            self,
            sections,
            first_line_index,
            last_line_index
            ):
        section = {
            'first_line': first_line_index,
            'last_line': last_line_index
            }

        if not 'header' in sections:
            sections['header'] = section
        elif not 'body' in sections:
            sections['body'] = section
        else:
            if not 'others' in sections:
                sections['others'] = []
            sections['others'].append(
                section
                )
        return

    def calculate_section_lines(self, log, stop_event):

        ret = 0

        lines_count = self.get_data_lines_count()

        sections = {}

        first_line_index = 0

        for i in range(lines_count):

            if stop_event is not None and stop_event.is_set():
                break

            line = self.get_data_line(i)

            if line == wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR:

                self._calculate_section_lines_sub_01(
                    sections,
                    first_line_index,
                    i - 1
                    )
                first_line_index = i + 1

        self._calculate_section_lines_sub_01(
            sections,
            first_line_index,
            lines_count - 1
            )

        self.set_section_lines(sections)

        return ret

    def calculate_subject(self, log, stop_event):
        """
        return:
        True - title found. everything is ok
        False - title not found. it's not consequance of errors
        None - error occured or stopped by event
        """

        ret = False

        lines_count = self.get_data_lines_count()

        title = None

        for i in range(lines_count):

            if stop_event is not None and stop_event.is_set():
                break

            line = self.get_data_line(i)

            if line.lower().startswith(b'subject:'):
                colon = line.find(b':')
                title = line[colon + 1:-2]
                title = str(title, 'utf-8')
                if title.startswith(' '):
                    title = title[1:]
                ret = True
                break

        self.set_subject(title)

        return ret

    def setup_initial_flags(self, log, stop_event):
        self.set_seen(False)
        self.set_answered(False)
        self.set_flagged(False)
        self.set_deleted(False)
        self.set_draft(False)
        self.set_recent(False)
        return

    def import_from_transition(self, transition_message_obj, log=None):

        if not isinstance(transition_message_obj, TransitionMessage):
            raise TypeError(
                "`transition_message_obj' must be inst of TransitionMessage"
                )

        self.makedirs()

        flags_list = transition_message_obj.flagged.get_flags_list()

        for i in flags_list:

            src_path = transition_message_obj.flagged.get_flag_path(i)
            dst_path = self.flagged.get_flag_path(i)

            if log is not None:
                log.info("Copying:")
                log.info("    '{}'".format(src_path))
                log.info("    to")
                log.info("    '{}'".format(dst_path))

            if not os.path.isfile(src_path):
                log.info("    source file does not exists")
            else:
                size = os.stat(src_path).st_size
                mb_size = size / 1024 / 1024

                log.info("    size: {} bytes ({} MiB)".format(size, mb_size))

                shutil.copy2(src_path, dst_path)

            log.info("")

        return


class MessageFlags(
        wayround_org.mail.server.directory_flag_methods.MessageFlagMethods
        ):

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

                # None or utc datetime
                'received-date',

                # list of int or None
                #    None - indicates what calculation didn't preformed or has
                #    been interrupted
                #
                # describes byte positions of lines in data
                'data-lines',

                # None or dict
                #    None - indicates what calculation didn't preformed or has
                #    been interrupted
                # dict must have following minimum structure. additional
                # fields may be added (probably it will be 'attachments'
                # section).
                # {'header': {'first_line': int, 'last_line': int},
                #  'body': {'first_line': int, 'last_line': int}}
                'section-lines',

                # None or str
                'subject',

                # list of dicts with attachment(s) data
                # {
                # 'first_line': int, # line index
                # 'last_line': int, # line index
                # 'content-type': str
                # }
                'attachments',

                # --v--V--v-- do no change names --v--V--v--
                # all flag values in this block are bool
                'seen',
                'answered',
                'flagged',
                'deleted',
                'draft',
                'recent',
                # --^--A--^-- do no change names --^--A--^--

                ],
            ['data']
            )


class TransitionMessage(MessageFlags, MessageIndexBuilder):

    """
    NOTE: TransitionMessage and Message are different by nature but have many
          similarities. this why __init__ is different
    """

    def __init__(self, spool_dir_obj, name):

        if not isinstance(spool_dir_obj, SpoolDirectory):
            raise TypeError("`spool_dir_obj' must be inst of SpoolDirectory")

        verify_mail_element_name(name)

        self._name = name

        if name.endswith('.data'):
            raise ValueError("`name' must not end with '.data'")

        super().__init__(
            wayround_org.utils.path.join(
                spool_dir_obj.path,
                'spool_conversion_tmp'
                ),
            self._name
            )

        self.path = self.gen_path()

        return

    def makedirs(self):
        dirname = os.path.dirname(self.path)
        os.makedirs(dirname, exist_ok=True)
        return

    def gen_path(self):
        return self.flagged.get_flag_path('data')


class Message(MessageFlags, LockableMailElement, MessageIndexBuilder):

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

        super().__init__(self._maildir_obj.path, self._name)

        self.path = self.gen_path()

        # self.attachments = MessageAttachments(self)

        return

    def gen_path(self):
        return self.flagged.get_flag_path('data')

    @property
    def name(self):
        return self._name

    def makedirs(self):
        ret = self._maildir_obj.makedirs()
        return ret

    def get_is_exists(self):
        return os.path.isfile(self.path)


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
            self,
            # wayround_org.utils.path.join(
            #    self.path,
            #    'spool_conversion_tmp'
            #    ),
            name
            )


class SpoolElement(
        wayround_org.mail.server.directory_flag_methods.MessageFlagMethods,
        LockableMailElement
        ):

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

                # None or utc datetime
                'received-date',

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
                # True if QUIT command processed successfuly
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

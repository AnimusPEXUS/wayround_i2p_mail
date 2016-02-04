
import yaml
import logging

import wayround_org.socketserver.server


class GeneralConfig:

    def __init__(self, data_dict):

        self.gid = None
        self.uid = None

        self.password_mode = 'plain'

        for i in ['gid', 'uid', 'password_mode']:
            if i in data_dict:
                setattr(self, i, data_dict[i])

        self.gid, self.uid = wayround_org.utils.osutils.convert_gid_uid(
            self.gid,
            self.uid
            )

        self.check_config()

        return

    def check_config(self):

        if not self.password_mode in ['plain']:
            raise ValueError(
                "general config: invalid `password_mode' value"
                )

        return


class DomainConfig:

    def __init__(self, data_dict):

        self.domain = data_dict['domain']
        self.sockets = []

        for i in data_dict['sockets']:
            self.sockets.append(SocketConfig(i))

        return


class SocketConfig:

    def __init__(self, data_dict):

        if not isinstance(data_dict, dict):
            raise TypeError(
                "`data_dict' must be dict"
                )

        self.address = '127.0.0.1'
        self.port = None
        self.protocol = None

        # ssl

        self.ssl = None
        self.ssl_mode = 'initial'
        self.starttls_required = True

        # for smtp

        self.smtp_mode = 'transport'
        self.smtp_auth_enabled = False

        # for imap

        for i in [
                'address',
                'port',
                'protocol',
                'ssl_mode',
                'starttls_required',
                'smtp_mode',
                'smtp_auth_enabled',
                ]:
            if i in data_dict:
                setattr(self, i, data_dict[i])

        if 'ssl' in data_dict:
            self.ssl = wayround_org.socketserver.server.SSLConfig(
                data_dict['ssl']
                )

        self.check_config()

        return

    def repr_as_text(self):
        ssl_txt = None
        if self.ssl is not None:
            ssl_txt = self.ssl.repr_as_text()
        ret = ("proto: {}, addr: {}, "
               "port: {:5}, SSL: [{}], SSL_mode: {}").format(
            self.protocol,
            self.address,
            self.port,
            ssl_txt,
            self.ssl_mode
            )
        return ret

    def check_config(self):
        if not self.protocol in ['smtp', 'imap']:
            raise ValueError(
                "socket protocol must be in ['smtp', 'imap']"
                )

        if not self.ssl_mode in ['initial', 'starttls']:
            raise ValueError(
                "socket ssl_mode must be in ['initial', 'starttls']"
                )

        if self.protocol == 'smtp':

            if not self.smtp_mode in ['transport', 'submission']:
                raise ValueError(
                    "if protocol == 'smtp', then smtp_mode must "
                    "be in ['transport', 'submission']"
                    )

        elif self.protocol == 'imap':
            pass
        else:
            raise Exception("programming error")

        if not isinstance(self.port, int):
            raise ValueError("port should int")

        if self.port < 0:
            raise ValueError("port should be positive int")

        return


def read_from_fs(filename):

    ret = None

    with open(filename) as f:
        txt = f.read()

    loaded = yaml.load(txt)

    res = correctness_check(loaded)

    if res == False:
        ret = None
    else:
        ret = loaded

    return loaded


def _correctness_check_application(data_dict, application):

    ret = True

    if ret:
        if not isinstance(application, dict):
            logging.error(
                "configuration: application configuration must be dict")
            ret = False

    if ret:
        for i in APPLICATION_KEYS:
            if not i in application:
                logging.error(
                    "configuration: application config requires `{}' key".format(
                        i
                        )
                    )
                ret = False

        for i in list(application.keys()):
            if not i in APPLICATION_KEYS and not i in APPLICATION_KEYS_OPT:
                logging.error(
                    "configuration: unknown "
                    "key (`{}') found in application config".format(
                        i
                        )
                    )
                ret = False

    # NOTE and TODO: here most likely mest be more checks

    return ret


def _correctness_check_socket(data_dict, socket):

    ret = True

    if ret:
        if not isinstance(socket, dict):
            logging.error("configuration: socket configuration must be dict")
            ret = False

    if ret:
        for i in SOCKET_KEYS:
            if not i in socket:
                logging.error(
                    "configuration: application config requires `{}' key".format(
                        i
                        )
                    )
                ret = False

        for i in list(socket.keys()):
            if not i in SOCKET_KEYS and not i in SOCKET_KEYS_OPT:
                logging.error(
                    "configuration: unknown "
                    "key (`{}') found in socket config".format(
                        i
                        )
                    )
                ret = False

        if 'SSL' in socket:
            if not _correctness_check_SSL(data_dict, socket['SSL']):
                logging.error(
                    "configuration: incorrect SSL config: `{}'".format(
                        socket['SSL']
                        )
                    )
                ret = False

    # NOTE and TODO: here most likely mest be more checks

    return ret


def _correctness_check_SSL(data_dict, ssl):

    ret = True

    if ret:
        if not isinstance(ssl, dict):
            logging.error("configuration: ssl configuration must be dict")
            ret = False

    if ret:
        for i in SSL_KEYS:
            if not i in ssl:
                logging.error(
                    "configuration: ssl config requires `{}' key".format(
                        i
                        )
                    )
                ret = False

        for i in list(ssl.keys()):
            if not i in SSL_KEYS and not i in SSL_KEYS_OPT:
                logging.error(
                    "configuration: unknown "
                    "key (`{}') found in ssl config".format(
                        i
                        )
                    )
                ret = False

    # NOTE and TODO: here most likely mest be more checks

    return ret


def correctness_check(data_dict):
    """
    result: True - Ok, False - Error
    """

    ret = True

    if ret:
        if not isinstance(data_dict, dict):
            logging.error("configuration: input data must be dict")
            ret = False

    if ret:

        for i in ['applications', 'sockets']:
            if not i in data_dict:
                logging.error(
                    "configuration: input data dict must have `{}' key".format(
                        i
                        )
                    )
                ret = False
                break

    if ret:
        for each in data_dict['applications']:
            if not _correctness_check_application(data_dict, each):
                logging.error(
                    "configuration: incorrect application config: `{}'".format(
                        each
                        )
                    )
                ret = False
                break

        for each in data_dict['sockets']:
            if not _correctness_check_socket(data_dict, each):
                logging.error(
                    "configuration: incorrect socket config: `{}'".format(
                        each
                        )
                    )
                ret = False
                break

    return ret

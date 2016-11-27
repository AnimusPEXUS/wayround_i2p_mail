
import os
import time
import threading
import socket
import ssl

import wayround_i2p.utils.path
import wayround_i2p.utils.osutils
import wayround_i2p.utils.socket

import wayround_i2p.socketserver.service

import wayround_i2p.mail.imap
import wayround_i2p.mail.miscs
import wayround_i2p.mail.server.config
import wayround_i2p.mail.server.directory
import wayround_i2p.mail.server.server_imap_session
import wayround_i2p.mail.server.server_smtp_session
import wayround_i2p.mail.server.socket
import wayround_i2p.mail.server.spool
import wayround_i2p.mail.smtp


class Domain:

    def __init__(
            self,
            server_obj,
            domain_config,
            callable_target
            ):

        if not isinstance(server_obj, Server):
            raise TypeError("invalid `server_obj' type")

        if not isinstance(
                domain_config,
                wayround_i2p.mail.server.config.DomainConfig
                ):
            raise TypeError("invalid `domain_config' type")

        self.server_obj = server_obj
        self.cfg = domain_config
        self.callable_target = callable_target

        self.sockets = None

        self.logger = self.server_obj.logger
        self.logger_error = self.server_obj.logger_error

        return

    def start(self):

        self.logger.info("        starting sockets")

        self.sockets = wayround_i2p.socketserver.service.SocketServicePool2()

        for i in self.cfg.sockets:
            self.logger.info("            {}".format(i.repr_as_text()))
            self.sockets.append(
                wayround_i2p.mail.server.socket.SocketService(
                    i,
                    self.callable_target_for_socket_pools
                    )
                )

        self.sockets.start()

        return

    def stop(self):
        if self.sockets:
            self.sockets.stop()
        return

    def wait(self):
        if self.sockets:
            self.sockets.wait()
        return

    def callable_target_for_socket_pools(
            self,
            utc_datetime,
            serv,
            serv_stop_event,
            sock,
            addr,
            service
            ):
        t = threading.Thread(
            name="Domain `{}' thread".format(self.cfg.domain),
            target=self.callable_target,
            args=(
                utc_datetime,
                serv,
                serv_stop_event,
                sock,
                addr,
                service,
                self
                )
            )

        t.start()
        return


class Server:

    def __init__(
            self,
            data_dir_path
            ):

        self.data_dir_path = wayround_i2p.utils.path.abspath(data_dir_path)

        self.directory = wayround_i2p.mail.server.directory.RootDirectory(
            self.data_dir_path
            )

        self.smtp_WITH_info_string = 'WROMS (0.0)'

        self.cfg = None

        self.general_cfg = None

        self.domains = []

        self.cfg = self.directory.get_config()

        self.general_cfg = wayround_i2p.mail.server.config.GeneralConfig(
            self.cfg['general']
            )

        self._stop_event = threading.Event()

        self.logger = None
        self.logger_error = None

        self.spooler = None

        return

    def start(self):

        self._stop_event.clear()

        self.logger = self.directory.create_normal_logger(
            self.general_cfg.gid,
            self.general_cfg.uid
            )
        self.logger_error = self.directory.create_error_logger(
            self.general_cfg.gid,
            self.general_cfg.uid
            )

        self.logger.info("starting server")

        self.spooler = wayround_i2p.mail.server.spool.SpoolWorker(
            self
            )

        self.logger.info("configuring domains")
        for i in self.cfg['domains']:
            self.logger.info("    domain [{}]".format(i['domain']))
            self.domains.append(
                Domain(
                    self,
                    wayround_i2p.mail.server.config.DomainConfig(i),
                    self.callable_target_for_socket_pools
                    )
                )

        for i in self.domains:
            i.start()

        if self.general_cfg.gid is not None:
            os.setregid(
                self.general_cfg.gid,
                self.general_cfg.gid
                )

        if self.general_cfg.uid is not None:
            os.setreuid(
                self.general_cfg.uid,
                self.general_cfg.uid
                )

        self.directory.get_spool_directory().makedirs()
        self.directory.get_permanent_memory().init()

        return

    def stop(self):

        self._stop_event.set()

        time.sleep(1)

        for i in self.domains:
            print("stopping domain {}".format(i))
            i.stop()

        if self.logger is not None:
            self.logger.stop()
        if self.logger_error is not None:
            self.logger_error.stop()
        return

    def wait(self):
        for i in self.domains:
            i.wait()
        return

    def wait_for_shutdown(self):
        print("Press CTRL+C to shutdown")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("CTRL+C pressed - shutting down.. please wait..")
        self.stop()
        self.wait()
        return

    def auth_user(self, domain, user, input_password_data, method='PLAIN'):
        """
        return: True - authenticated, False - not authenticated. None - error
        """

        print("TODO: auth_user: input data checks!")

        ret = None

        if (not self.directory.get_is_user_exists(domain, user)
                or not self.directory.get_is_user_enabled(domain, user)
                ):
            print(
                "user `{}@{}' exists ({}) and enabled ({})".format(
                    user,
                    domain,
                    self.directory.get_is_user_exists(domain, user),
                    self.directory.get_is_user_enabled(domain, user)
                    )
                )
            ret = False
        else:
            pwd_mode = self.general_cfg.password_mode

            domain_obj = self.directory.get_domain(domain)

            user_obj = domain_obj.get_user(user)

            local_user_password_data = user_obj.get_password_data()

            # TODO: add other storage methods

            if pwd_mode == 'plain':

                ret = input_password_data == local_user_password_data

            else:
                raise Exception("programming error")

        print("auth '{}@{}' ret: {}".format(user, domain, ret))

        return ret

    def callable_target_for_socket_pools(
            self,
            utc_datetime,
            serv,
            serv_stop_event,
            sock,
            addr,
            service,
            domain
            ):
        session_logger = self.directory.create_session_logger(
            name='{}-{}'.format(
                service.cfg.protocol,
                utc_datetime
                ),
            timestamp=str(utc_datetime)
            )

        session_logger.info(
            '{timestamp} {type_} {to_domain}'
            ' {from_addr}'
            ' {to_addr}'
            .format(
                timestamp=utc_datetime,
                type_=service.cfg.protocol,
                to_domain=domain.cfg.domain,
                from_addr=addr,
                to_addr=service.cfg.repr_as_text()
                )
            )

        if service.cfg.protocol == 'imap':
            imap_session = \
                wayround_i2p.mail.server.server_imap_session.\
                ImapSessionHandler(
                    self,
                    utc_datetime,
                    serv,
                    serv_stop_event,
                    sock,
                    addr,
                    service,
                    domain,
                    session_logger
                    )
            imap_session.loop_enter()
        elif service.cfg.protocol == 'smtp':
            smtp_session = \
                wayround_i2p.mail.server.server_smtp_session.\
                SmtpSessionHandler(
                    self,
                    utc_datetime,
                    serv,
                    serv_stop_event,
                    sock,
                    addr,
                    service,
                    domain,
                    session_logger
                    )
            smtp_session.loop_enter()
        else:
            raise Exception("programming error")
        session_logger.stop()
        return

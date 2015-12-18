
import os
import time
import threading

import wayround_org.utils.path
import wayround_org.utils.osutils
import wayround_org.utils.socket

import wayround_org.socketserver.service

import wayround_org.mail.server.config
import wayround_org.mail.server.socket
import wayround_org.mail.miscs

import wayround_org.mail.server.directory


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
                wayround_org.mail.server.config.DomainConfig
                ):
            raise TypeError("invalid `domain_config' type")

        self.server_obj = server_obj
        self.domain_config = domain_config
        self.callable_target = callable_target

        self.sockets = None

        self.logger = self.server_obj.logger
        self.logger_error = self.server_obj.logger_error

        return

    def start(self):

        self.logger.info("        starting sockets")

        self.sockets = wayround_org.socketserver.service.SocketServicePool2()

        for i in self.domain_config.sockets:
            self.logger.info("            {}".format(i.repr_as_text()))
            self.sockets.append(
                wayround_org.mail.server.socket.SocketService(
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
            name="Domain `{}' thread".format(self.domain_config.domain),
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

        self.data_dir_path = wayround_org.utils.path.abspath(data_dir_path)

        self.directory_tree = None

        self.cfg = None

        self.gid = None
        self.uid = None

        self.domains = []

        self.directory_tree = wayround_org.mail.server.directory.RootDirectory(
            self.data_dir_path
            )

        self.cfg = self.directory_tree.get_config()
        
        self._stop_event = threading.Event()

        self.logger = None
        self.logger_error = None

        return

    def start(self):

        self._stop_event.clear()

        self.logger = self.directory_tree.create_normal_logger()
        self.logger_error = self.directory_tree.create_error_logger()

        self.logger.info("starting server")

        self.logger.info("configuring domains")
        for i in self.cfg['domains']:
            self.logger.info("    domain [{}]".format(i['domain']))
            self.domains.append(
                Domain(
                    self,
                    wayround_org.mail.server.config.DomainConfig(i),
                    self.callable_target_for_socket_pools
                    )
                )

        for i in self.domains:
            i.start()

        self.gid = None
        self.uid = None

        try:
            self.gid = self.cfg['general']['gid']
        except KeyError:
            pass
        except TypeError:
            pass

        try:
            self.uid = self.cfg['general']['uid']
        except KeyError:
            pass
        except TypeError:
            pass

        self.gid, self.uid = wayround_org.utils.osutils.convert_gid_uid(
            self.gid, self.uid
            )

        if self.gid is not None:
            os.setregid(self.gid, self.gid)

        if self.uid is not None:
            os.setreuid(self.uid, self.uid)

        return

    def stop(self):
        
        self._stop_event.set()
    
        for i in self.domains:
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
        session_logger = self.directory_tree.create_session_logger(
            timestamp=utc_datetime
            )

        session_logger.info(
            '{timestamp} {type_} {to_domain}'
            ' {from_addr} {from_port}'
            ' {to_addr} {to_port}'
            .format(
                utc_datetime,
                serv,
                serv_stop_event,
                sock,
                addr,
                service,
                domain
                )
            )

        if service.cfg.protocol == 'imap':
            self.imap_session(
                utc_datetime,
                serv,
                serv_stop_event,
                sock,
                addr,
                service,
                domain,
                session_logger
                )
        elif service.cfg.protocol == 'smtp':
            self.smtp_session(
                utc_datetime,
                serv,
                serv_stop_event,
                sock,
                addr,
                service,
                domain,
                session_logger
                )
        else:
            raise Exception("programming error")
        session_logger.stop()
        return

    def imap_session(
            self,
            utc_datetime,
            serv,
            serv_stop_event,
            sock,
            addr,
            service,
            domain
            ):
        lbl_reader = wayround_org.utils.socket.LblRecvReaderBuffer(
            sock,
            # recv_size=4096,
            line_terminator=b'\0\n'
            )
        lbl_reader.start()
        sock.sendall(
            b'* OK IMAP4rev1 Service Ready'
            + wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
            )

        while True:
        
            if self._stop_event.is_set():
                break

            print(
                "[{}] waiting for input: {}".format(
                    utc_datetime,
                    line
                    )
                )
                
            line = lbl_reader.nb_get_next_line(self._stop_event)

            if self._stop_event.is_set():
                break
            
            if line == None:
                

            print(
                "[{}] got line from client: {}".format(
                    utc_datetime,
                    line
                    )
                )
    
        if self._stop_event.is_set():
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()

        lbl_reader.stop()
        return

    def smtp_session(
            self,
            utc_datetime,
            serv,
            serv_stop_event,
            sock,
            addr,
            service,
            domain
            ):
        return

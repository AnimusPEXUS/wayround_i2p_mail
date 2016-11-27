
import socket
import ssl

import wayround_i2p.socketserver.server
import wayround_i2p.socketserver.service

import wayround_i2p.mail.server.config


class SocketService:
    """

    this class (or it's instances) is not intended for direct initialization.

    it's created, used and destroyed by SocketPool class instance
    """

    def __init__(self, cfg, callable_target):

        if not isinstance(cfg, wayround_i2p.mail.server.config.SocketConfig):
            raise TypeError(
                "`cfg' must be of type"
                " wayround_i2p.mail.server.config.SocketConfig"
                )

        self.cfg = cfg

        self._callable_target = callable_target

        self.socket = None

        self.socket_server = wayround_i2p.socketserver.server.SocketServer(
            self.socket,
            self.target,
            ssl_config=self.cfg.ssl,
            thread_name="SocketServer Thread for {}".format(cfg.repr_as_text())
            )

        return

    def start(self):

        s = socket.socket()

        s.setblocking(False)

        try:
            s.bind((self.cfg.address, self.cfg.port))
        except OSError as err:
            if err.args[0] == 98:
                print(
                    "Tryed to bind port {} on address: {}".format(
                        self.cfg.port,
                        self.cfg.address
                        )
                    )
            raise

        s.listen(5)  # TODO: configure for this argument

        self.socket_server.set_sock(s)

        if self.socket_server.get_is_ssl_config_defined():
            self.socket_server.wrap()

        self.socket = self.socket_server.get_sock()

        self.socket_server.start()

        return

    def stop(self):
        if self.socket:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        self.socket_server.stop()
        return

    def wait(self):
        self.socket_server.wait()
        return

    def target(
            self,
            transaction_id,
            serv,
            serv_stop_event,
            sock,
            addr
            ):

        self._callable_target(
            transaction_id,
            serv,
            serv_stop_event,
            sock,
            addr,
            self
            )

        return

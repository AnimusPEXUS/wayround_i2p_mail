
import socket

import wayround_org.utils.socket

import wayround_org.sasl.sasl

import wayround_org.mail.miscs
import wayround_org.mail.server.server
import wayround_org.mail.smtp


class SmtpSessionHandler:

    def __init__(self, server, utc_datetime,
                 socket_server,
                 socket_server_stop_event,
                 accepted_socket,
                 accepted_address,
                 service,
                 domain,
                 session_logger
                 ):

        if not isinstance(server, wayround_org.mail.server.server.Server):
            raise TypeError(
                "`server' must be of type "
                "wayround_org.mail.server.server.Server"
                )

        self.server = server

        self._stop_event = self.server._stop_event

        self.utc_datetime = utc_datetime
        self.socket_server = socket_server
        self.accepted_socket = accepted_socket
        self.service = service
        self.domain = domain

        self.socket_server_stop_event = socket_server_stop_event
        self.accepted_address = accepted_address
        self.session_logger = session_logger

        self.lbl_reader = None

        return

    def start(self):
        wayround_org.utils.socket.nb_handshake(self.accepted_socket)

        self.lbl_reader = wayround_org.utils.socket.LblRecvReaderBuffer(
            self.accepted_socket,
            # recv_size=4096,
            line_terminator=wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
            )
        self.lbl_reader.start()

        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            # TODO: this must be configurable
            bytes('220 {}'.format(self.domain.cfg.domain), 'utf-8')
            + wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
            )

        while True:

            if self._stop_event.is_set():
                break

            self.session_logger.info("waiting for input")

            line = self.lbl_reader.nb_get_next_line(self._stop_event)

            if line == wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR:
                self.session_logger.info("client closed connection")
                break

            if self._stop_event.is_set():
                break

            self.session_logger.info("got line from client: {}".format(line))

            parsed_cmd_line = wayround_org.mail.smtp.c2s_command_line_parse(
                line
                )
            self.session_logger.info("parsed line: {}".format(parsed_cmd_line))

            if parsed_cmd_line is None:
                self.session_logger.error(
                    "can't parse line: {}".format(line[:100])
                    )
                break

            line_parsed_command = parsed_cmd_line['command']

            cmd_method_name = 'cmd_{}'.format(line_parsed_command)

            if hasattr(self, cmd_method_name):
                cmd_method = getattr(self, cmd_method_name)

                cmd_method(line_parsed_command, parsed_cmd_line['rest'])

            else:
                response = wayround_org.mail.smtp.s2c_response_format(
                    502,
                    True,
                    'Command not implemented'
                    )

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    response
                    )

        if self._stop_event.is_set():
            self.accepted_socket.shutdown(socket.SHUT_RDWR)
            self.accepted_socket.close()

        self.lbl_reader.stop()

        return

    def cmd_EHLO(self, cmd, rest):

        response = b''

        client_name = 'you'
        if len(rest) != 0:
            client_name = rest[0]

        response += wayround_org.mail.smtp.s2c_response_format(
            250,
            False,
            '{} greets {}'.format(
                self.domain.cfg.domain,
                client_name
                )
            )

        resp_lines = ['8BITMIME', 'SIZE', 'DSN', 'HELP']

        for i in resp_lines[:-1]:
            response += wayround_org.mail.smtp.s2c_response_format(
                250,
                False,
                i
                )

        response += wayround_org.mail.smtp.s2c_response_format(
            250,
            True,
            resp_lines[-1]
            )

        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            response
            )
        return

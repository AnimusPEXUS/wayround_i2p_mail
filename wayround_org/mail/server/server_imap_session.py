

import socket

import wayround_org.utils.socket

import wayround_org.sasl.sasl

import wayround_org.mail.miscs
import wayround_org.mail.server.server
import wayround_org.mail.imap


class ImapSessionHandler:

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
        return

        wayround_org.utils.socket.nb_handshake(self.accepted_socket)

        self.lbl_reader = wayround_org.utils.socket.LblRecvReaderBuffer(
            self.accepted_socket,
            # recv_size=4096,
            line_terminator=wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR
            )
        self.lbl_reader.start()

        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            b'* OK IMAP4rev1 Service Ready'
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

            parsed_cmd_line = wayround_org.mail.imap.c2s_command_line_parse(
                line
                )
            self.session_logger.info("parsed line: {}".format(parsed_cmd_line))

            if parsed_cmd_line is None:
                self.session_logger.error(
                    "can't parse line: {}".format(line[:100])
                    )
                break

            line_parsed_tag = parsed_cmd_line['tag']
            line_parsed_command = parsed_cmd_line['command']

            cmd_method_name = 'cmd_{}'.format(line_parsed_command)

            if hasattr(self, cmd_method_name):
                cmd_method = getattr(self, cmd_method_name)

                cmd_method(
                    line_parsed_tag,
                    line_parsed_command,
                    parsed_cmd_line['rest']
                    )

            else:
                response = wayround_org.mail.imap.s2c_response_format(
                    line_parsed_tag,
                    'BAD',
                    line_parsed_command
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

    def cmd_CAPABILITY(self, tag, cmd, rest):

        line_parsed_tag = tag
        line_parsed_command = cmd

        response = b''

        caps = [
            'CAPABILITY',
            'IMAP4rev1'
            ]

        '''
        if (service.cfg.ssl_mode == 'starttls'
                and service.cfg.ssl is not None):
            caps.append('STARTTLS')
        '''

        # caps.append('STARTTLS')
        # caps.append('LOGINDISABLED')
        caps.append('AUTH=PLAIN')

        response += bytes(
            '* {}'.format(' '.join(caps)),
            'utf-8'
            ) + wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

        response += wayround_org.mail.imap.s2c_response_format(
            line_parsed_tag,
            'OK',
            line_parsed_command + ' completed'
            )

        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            response
            )

        return

    def cmd_AUTHENTICATE(self, tag, cmd, rest):

        line_parsed_tag = tag
        line_parsed_command = cmd

        asked_method = parsed_cmd_line['rest'][0]
        asked_method = asked_method.upper()

        bad = False
        no = False

        sasl = wayround_org.sasl.sasl.init_mech('PLAIN', 'server')

        bad, no = self.server_authenticate(sasl, line_parsed_tag)

        if bad and no:
            raise Exception("programming error")

        if bad:
            response = wayround_org.mail.imap.s2c_response_format(
                line_parsed_tag,
                'BAD',
                line_parsed_command
                )

            wayround_org.utils.socket.nb_sendall(
                self.accepted_socket,
                response
                )

        if no:
            response = wayround_org.mail.imap.s2c_response_format(
                line_parsed_tag,
                'NO',
                line_parsed_command
                )

            wayround_org.utils.socket.nb_sendall(
                self.accepted_socket,
                response
                )

        return

    def server_authenticate(self, sasl, line_parsed_tag):

        buf = ''
        step = 0

        bad = False
        no = False

        while True:
            self.session_logger.info("step {}".format(step))
            rcr = sasl.step64(buf)

            print("rcr: {}".format(rcr))

            if rcr[0] == 'need_more':

                request = b'+'

                if len(rcr[0]) != 0:
                    request += bytes(
                        ' {}'.format(str(rcr[1], 'utf-8')),
                        'utf-8'
                        )

                request += wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    request
                    )

                buf = self.lbl_reader.nb_get_next_line(
                    self._stop_event
                    )

                if (buf == wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR):
                    self.session_logger.error(
                        'connection closed by client unexpectedly'
                        )
                    break

                elif (buf == b'*' + wayround_org.mail.miscs.STANDARD_LINE_TERMINATOR):
                    self.session_logger.error(
                        'client wished to cancel authentication'
                        )
                    bad = True
                    break

            elif rcr[0] == 'ok':

                request = wayround_org.mail.imap.s2c_response_format(
                    line_parsed_tag,
                    'OK',
                    "PLAIN authentication successful"
                    )

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    request
                    )

                break

            else:
                break

            step += 1
        return bad, no

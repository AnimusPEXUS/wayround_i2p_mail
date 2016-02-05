
import socket
import threading
import time
import ssl
import datetime

import wayround_org.utils.socket

import wayround_org.sasl.sasl

import wayround_org.mail.miscs
import wayround_org.mail.server.server
import wayround_org.mail.smtp


class SmtpSessionHandler:

    def __init__(
            self,
            server,
            utc_datetime,
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

        # server connection
        self.server = server

        # session specific objects
        self.utc_datetime = utc_datetime
        self.socket_server = socket_server
        self.accepted_socket = accepted_socket
        self.service = service
        self.domain = domain
        self.socket_server_stop_event = socket_server_stop_event
        self.accepted_address = accepted_address
        self.session_logger = session_logger

        # break system
        self._server_stop_event = self.socket_server_stop_event
        self._stop_event = threading.Event()
        self._stopped_event = threading.Event()

        # stream reader
        self.lbl_reader = None

        # directory access
        self.directory = self.server.directory
        self.spool_directory = self.directory.get_spool_directory()
        self.actual_spool_element = self.spool_directory.new_element()

        # current user auth. this value not None only if user really passed
        # authentication and really authenticated.
        # None - means user not authenticated
        self.user_requested_auth = None

        # TODO: password brut force pickup protection needed

        return

    def _server_stop_watcher(self):
        while True:
            if self._server_stop_event.is_set():
                break

            if self._stop_event.is_set():
                break

            time.sleep(1)

        threading.Thread(target=self.stop).start()

        return

    def loop_enter(self):

        threading.Thread(target=self._server_stop_watcher).start()

        wayround_org.utils.socket.nb_handshake(self.accepted_socket)

        self.session_logger.info("Certificate info")
        self.session_logger.info("    base:")
        if isinstance(self.accepted_socket, ssl.SSLSocket):
            ssl_info = self.accepted_socket.cipher()
            self.session_logger.info(
                "        {}:{}:{}".format(
                    ssl_info[1],
                    ssl_info[0],
                    ssl_info[2]
                    )
                )
        else:
            self.session_logger.info("        none")

        self.actual_spool_element.set_auth_as(None)
        self.actual_spool_element.set_to_finished(False)
        self.actual_spool_element.set_quit_ok(False)

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
            line_parsed_rest = parsed_cmd_line['rest']

            print("cmd recognised: {}".format(line_parsed_command))
            print("params        : {}".format(line_parsed_rest))

            authenticated = self.user_requested_auth is not None
            cmd_requires_auth = (
                line_parsed_command
                in wayround_org.mail.smtp.AUTHLESS_COMMANDS
                )

            # TODO: this is probaby must be wizer
            this_port_requires_auth = (
                self.service.cfg.smtp_mode == 'submission'
                )

            error = False

            if (this_port_requires_auth
                    and cmd_requires_auth
                    and not authenticated):

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        530,
                        True,
                        'Authentication required'
                        )
                    )

                error = True

            if not error:

                cmd_method_name = 'cmd_{}'.format(line_parsed_command)

                if hasattr(self, cmd_method_name):

                    cmd_method = getattr(self, cmd_method_name)
                    cmd_method(line_parsed_command, line_parsed_rest)

                else:

                    wayround_org.utils.socket.nb_sendall(
                        self.accepted_socket,
                        wayround_org.mail.smtp.s2c_response_format(
                            502,
                            True,
                            'Command not implemented'
                            )
                        )

            if self._server_stop_event.is_set():
                self.session_logger.warning(
                    "SMTP session {} at port {}"
                    " recvd 'stop' signal from server".format(
                        self,
                        self.service.cfg.port
                        )
                    )

            if self._stop_event.is_set():
                self.session_logger.info(
                    "SMTP session {} at port {}"
                    " recvd 'stop' signal from internals".format(
                        self,
                        self.service.cfg.port
                        )
                    )

        self.lbl_reader.stop()

        threading.Thread(target=self.stop).start()

        self.accepted_socket.shutdown(socket.SHUT_RDWR)
        self.accepted_socket.close()

        self._stopped_event.set()

        return

    def stop(self):
        if self.lbl_reader is not None:
            self.lbl_reader.stop()
        self._stop_event.set()
        self._stopped_event.wait()
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

        resp_lines = [
            '8BITMIME',
            'SIZE',
            'DNS',
            'HELP',

            'AUTH PLAIN'
            ]

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

    def cmd_AUTH(self, cmd, rest):

        rest_l = len(rest)

        error = False

        if not error:
            if self.user_requested_auth is not None:

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        503,
                        True,
                        'Bad sequence of commands'
                        )
                    )

                error = True

        if not error:

            if rest_l < 1:

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        500,
                        True,
                        'Syntax error, command unrecognized'
                        )
                    )

                error = True

        if not error:

            mechanism = rest[0].upper()

            if mechanism not in ['PLAIN']:

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        504,
                        True,
                        'Command parameter not implemented'
                        )
                    )

                error = True

        if not error:

            if rest_l == 1:

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(334, True, '')
                    )

                request = self.lbl_reader.nb_get_next_line(self._stop_event)

            if rest_l == 2:

                request = rest[1]

            else:

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        500,
                        True,
                        'Syntax error, command unrecognized'
                        )
                    )

                error = True

        if not error:

            sasl_session = wayround_org.sasl.sasl.init_mech('PLAIN', 'server')

            res_0, res_1 = sasl_session.step64(request)

            sasl_session_authzid = sasl_session['authzid']
            sasl_session_authcid = sasl_session['authcid']
            sasl_session_passwd = sasl_session['passwd']

            # not needed
            del sasl_session

            print(
                "SASL plain server mech responded: {}".format(
                    (res_0, res_1)
                    )
                )
            print(
                """\
SASL results:
authzid '{}',
authcid '{}',
passwd: '{}'
""".format(
                    sasl_session_authzid,
                    sasl_session_authcid,
                    sasl_session_passwd
                    )
                )

            # authzid is not supported, so if provided - it's an error
            if res_0 == 'ok' and len(sasl_session_authzid) == 0:
                auth_user_res = self.server.auth_user(
                    self.domain.cfg.domain,
                    sasl_session_authcid,
                    sasl_session_passwd
                    )

                if auth_user_res == True:
                    self.user_requested_auth = {
                        'name': sasl_session_authcid,
                        'passwd': sasl_session_passwd
                        }

                    wayround_org.utils.socket.nb_sendall(
                        self.accepted_socket,
                        wayround_org.mail.smtp.s2c_response_format(
                            235,
                            True,
                            'Authentication successful'
                            )
                        )

                    self.actual_spool_element.set_auth_as(
                        wayround_org.mail.miscs.Address(
                            '{name}@{domain}'.format(
                                name=sasl_session_authcid,
                                domain=self.domain.cfg.domain
                                )
                            ).render_str()
                        )

                elif auth_user_res == False:

                    wayround_org.utils.socket.nb_sendall(
                        self.accepted_socket,
                        wayround_org.mail.smtp.s2c_response_format(
                            535,
                            True,
                            'Authentication credentials invalid'
                            )
                        )

                else:  # case of None, which should be not happen
                    raise Exception("programming error")

            else:

                # TODO: probably this should be considered as a programming
                #       error, as it shold not be happening if speaking only
                #       about PLAIN mechanism.
                #
                #       but other than PLAIN mechanisms can lead to this
                #       'else' leaf
                #
                #       this error shold not be accuring unnoticed
                #
                #       exception should not be raised: to not disrupt server
                #       work
                #
                #       more probably error shold be logged,
                #       but I've hasn't decided how it should be done
                #       exactly yet

                # raise Exception("programming error")

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        454,
                        True,
                        'Temporary authentication failure'
                        )
                    )

        return

    def _2x_cmd(self, cmd, rest, sub_cmd_callables_dict):

        sub_cmd = None

        rest_l = len(rest)

        if rest_l == 0:
            raise Exception("TODO: return error to client")
        else:
            rest0 = rest[0]

            if not ':' in rest0:
                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        500,
                        True,
                        'Syntax error, command unrecognized'
                        )
                    )
            else:
                semi = rest0.find(':')
                sub_cmd = rest0[:semi].upper().strip()

                if not sub_cmd in sub_cmd_callables_dict:
                    wayround_org.utils.socket.nb_sendall(
                        self.accepted_socket,
                        wayround_org.mail.smtp.s2c_response_format(
                            500,
                            True,
                            'Syntax error, command unrecognized'
                            )
                        )
                else:
                    sub_cmd = sub_cmd_callables_dict[sub_cmd]
                    print("calling {}".format(sub_cmd))
                    sub_cmd('{} {}'.format(cmd, sub_cmd), rest)

        return

    def cmd_MAIL(self, cmd, rest):
        self._2x_cmd('MAIL', rest, {'FROM': self.cmd_MAIL_FROM})
        return

    def cmd_MAIL_FROM(self, cmd, rest):
        from_val = rest[0].split(':', 1)[1]
        from_val = wayround_org.mail.miscs.Address.new_from_str(from_val)
        from_val.authority.userinfo.password = None
        self.actual_spool_element.set_from(
            from_val.authority.render_str()
            )

        if len(rest) > 1:
            rest1 = rest[1]
            if rest1.upper().startswith('SIZE='):
                size = int(rest1.split('=', 1)[1].strip())
                self.actual_spool_element.set_size(size)

        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            wayround_org.mail.smtp.s2c_response_format(
                250,
                True,
                'Ok'
                )
            )

        return

    def cmd_RCPT(self, cmd, rest):
        self._2x_cmd('RCPT', rest, {'TO': self.cmd_RCPT_TO})
        return

    def cmd_RCPT_TO(self, cmd, rest):
        to_val = rest[0].split(':', 1)[1]
        to_val = wayround_org.mail.miscs.Address.new_from_str(to_val)

        # saving this anyway, not depending on success or fault in destination
        # checks
        self.actual_spool_element.add_to(to_val.authority.render_str())

        if to_val.authority.userinfo is None:
            pass  # TODO: terminate client!

        # 'transport', 'submission'
        if self.service.cfg.smtp_mode == 'transport':
            if self.server.directory.get_is_user_enabled(
                    to_val.authority.host,
                    to_val.authority.userinfo.name
                    ):
                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        250,
                        True,
                        'Ok'
                        )
                    )
            else:
                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        550,
                        True,
                        'mailbox not found'
                        )
                    )

        elif self.service.cfg.smtp_mode == 'submission':
            # user assumed to be authenticated
            # so he's allowed anything
            wayround_org.utils.socket.nb_sendall(
                self.accepted_socket,
                wayround_org.mail.smtp.s2c_response_format(
                    250,
                    True,
                    'Ok'
                    )
                )
        else:
            raise Exception("programming error")

        return

    def cmd_DATA(self, cmd, rest):

        self.actual_spool_element.set_received(
            self.format_recieved_string()
            )

        self.actual_spool_element.set_received_date(
            datetime.datetime.utcnow()
            )

        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            wayround_org.mail.smtp.s2c_response_format(
                354,
                True,
                ''
                )
            )

        while True:
            line = self.lbl_reader.nb_get_next_line(self._stop_event)

            if self._stop_event.is_set():
                break

            if line.strip() == b'.':

                wayround_org.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_org.mail.smtp.s2c_response_format(
                        250,
                        True,
                        'Ok'
                        )
                    )

                self.actual_spool_element.set_to_finished(True)
                break

            self.actual_spool_element.append_data(line)

        return

    def cmd_QUIT(self, cmd, rest):
        wayround_org.utils.socket.nb_sendall(
            self.accepted_socket,
            wayround_org.mail.smtp.s2c_response_format(
                221,
                True,
                'Ok'
                )
            )

        self.actual_spool_element.set_quit_ok(True)

        threading.Thread(target=self.stop).start()

        t = threading.Thread(
            target=self.server.spooler.process_spool_element,
            args=(self.actual_spool_element.get_name(),)
            )
        t.start()

        return

    def format_recieved_string(self):
        peer_name = self.accepted_socket.getpeername()
        sock_name = self.accepted_socket.getsockname()
        # print("peer_name: {}, sock_name: {}".format(peer_name, sock_name))

        peer_info = socket.gethostbyaddr(peer_name[0])
        sock_info = socket.gethostbyaddr(sock_name[0])

        from_value = 'FROM {} ([{}])'.format(
            peer_info[0], peer_info[2][0]
            )

        by_value = 'BY {} ([{}])'.format(
            self.domain.cfg.domain,
            sock_info[2][0]
            )

        with_value = 'WITH'

        if isinstance(self.accepted_socket, ssl.SSLSocket):
            if self.service.cfg.ssl_mode == 'starttls':
                with_value += ' ESMTPS'
            elif self.service.cfg.ssl_mode == 'initial':
                with_value += ' SMTPS'
            else:
                raise Exception("programming error")
        else:
            with_value += ' SMTP'

        if isinstance(self.accepted_socket, ssl.SSLSocket):
            with_value += ' ('
            ssl_info = self.accepted_socket.cipher()
            with_value += '{}:{}:{}'.format(
                ssl_info[1],
                ssl_info[0],
                ssl_info[2]
                )
            with_value += ')'

        with_value += ' ' + self.server.smtp_WITH_info_string

        '''
        ret = bytes(
            '{} {} {}'.format(
                from_value,
                by_value,
                with_value
                ),
            'utf-8'
            )
        '''

        ret = '{} {} {}'.format(
            from_value,
            by_value,
            with_value
            )

        # print("format_recieved_string ret: {}".format(ret))

        return ret

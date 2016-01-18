
import socket

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

        # emergincy break
        self._stop_event = self.server._stop_event

        # stream reader
        self.lbl_reader = None

        # directory access
        self.directory = self.server.directory
        self.spool_directory = self.directory.get_spool_directory()
        self.actual_spool_element = self.spool_directory.new_element()

        # current user auth. this value None only if user really passed
        # authentication and really authenticated.
        # None - means user not authenticated
        self.user_requested_auth = None

        # TODO: password brut force pickup protection needed

        return

    def start(self):

        wayround_org.utils.socket.nb_handshake(self.accepted_socket)

        self.actual_spool_element.set_auth_as(None)

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

        resp_lines = [
            '8BITMIME',
            'SIZE',
            'DSN',
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

    def cmd_MAIL(self, cmd, rest):
        sub_cmd = None

        rest_l = len(rest)

        if rest_l == 0:
            pass
        else:
            rest0 = rest[0]
            if rest0.upper().startswith('FROM:'):
                sub_cmd = 'FROM'
            else:
                pass

        if sub_cmd is None:
            response = wayround_org.mail.smtp.s2c_response_format(
                500,
                True,
                'Syntax error, command unrecognized'
                )

            wayround_org.utils.socket.nb_sendall(
                self.accepted_socket,
                response
                )

        else:

            cmd_method_name = 'cmd_MAIL_{}'.format(sub_cmd)

            if hasattr(self, cmd_method_name):
                print("cmd recognised: {}".format(cmd_method_name))
                print("params        : {}".format(rest))

                cmd_method = getattr(self, cmd_method_name)
                cmd_method('MAIL {}'.format(sub_cmd), rest)

        # self.client_offered_message_size
        return

    def cmd_MAIL_FROM(self, cmd, rest):
        from_val = rest[0].split(':', 1)[1]
        from_val = wayround_org.mail.miscs.Address.new_from_str(from_val)
        self.actual_spool_element.set_from(from_val.render_dict())

        if len(rest) > 1:
            rest1 = rest[1]
            if rest1.upper().startswith('SIZE='):
                size = int(rest1.split('=', 1)[1].strip())
                self.actual_spool_element.set_size(size)

        return



import socket
import threading
import time
import ssl

import wayround_i2p.utils.socket
import wayround_i2p.utils.datetime_rfc5322
import wayround_i2p.utils.pm

import wayround_i2p.sasl.sasl

import wayround_i2p.mail.miscs
import wayround_i2p.mail.server.directory
import wayround_i2p.mail.server.server
import wayround_i2p.mail.imap


class MailDirSelection:

    def __init__(self, imap_session_handler, maildir):
        if not isinstance(imap_session_handler, ImapSessionHandler):
            raise TypeError(
                "`imap_session_handler' must be inst of ImapSessionHandler"
                )

        if not isinstance(
                maildir,
                wayround_i2p.mail.server.directory.MailDir
                ):
            raise TypeError(
                "`maildir' must be inst of "
                "wayround_i2p.mail.server.directory.MailDir"
                )

        self.imap_session_handler = imap_session_handler
        self.maildir = maildir
        return

    def render_status_text(self):
        """
        result is bytes ready to send to port
        """

        ret = wayround_i2p.mail.imap.format_mailbox_status_text(
            self.get_flags(),
            self.get_exists(),
            self.get_recent(),
            None,
            None,
            None,
            None
            )

        return ret

    def get_flags(self):
        return self.maildir.find_set_flags()

    def get_exists(self):
        return len(self.maildir.get_message_list())

    def get_recent(self):
        return len(self.maildir.get_recent_message_list())


class ImapSessionHandler:

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

        if not isinstance(server, wayround_i2p.mail.server.server.Server):
            raise TypeError(
                "`server' must be of type "
                "wayround_i2p.mail.server.server.Server"
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

        # current user auth. this value not None only if user really passed
        # authentication and really authenticated.
        # None - means user not authenticated
        self.user_requested_auth = None
        self.user_obj = None

        self.selected_mailbox = None

        self.permanent_memory = self.directory.get_permanent_memory()

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

        wayround_i2p.utils.socket.nb_handshake(self.accepted_socket)

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

        self.lbl_reader = wayround_i2p.utils.socket.LblRecvReaderBuffer(
            self.accepted_socket,
            # recv_size=4096,
            line_terminator=wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR
            )
        self.lbl_reader.start()

        wayround_i2p.utils.socket.nb_sendall(
            self.accepted_socket,
            b'* OK IMAP4rev1 Service Ready'
            + wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR
            )

        while True:

            if self._stop_event.is_set():
                break

            self.session_logger.info("waiting for input")

            line = self.lbl_reader.nb_get_next_line(self._stop_event)

            if line is None:
                break

            if line == wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR:
                self.session_logger.info("client closed connection")
                break

            if self._stop_event.is_set():
                break

            self.session_logger.info("got line from client: {}".format(line))

            parsed_cmd_line = wayround_i2p.mail.imap.c2s_command_line_parse(
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
                    parsed_cmd_line['parameters']
                    )

            else:

                wayround_i2p.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_i2p.mail.imap.s2c_response_format(
                        line_parsed_tag,
                        'BAD',
                        line_parsed_command
                        )
                    )

            if self._server_stop_event.is_set():
                self.session_logger.warning(
                    "IMAP session {} at port {}"
                    " recvd 'stop' signal from server".format(
                        self,
                        self.service.cfg.port
                        )
                    )

            if self._stop_event.is_set():
                self.session_logger.info(
                    "IMAP session {} at port {}"
                    " recvd 'stop' signal from internals".format(
                        self,
                        self.service.cfg.port
                        )
                    )

        self.session_logger.info("command line loop exited")

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

    def set_selection(self, mailbox):

        if mailbox is not None and not isinstance(
                mailbox,
                (
                    wayround_i2p.mail.server.directory.MailDir,
                    MailDirSelection
                    )
                ):
            raise TypeError(
                "`mailbox' must be None or MailDir or MailDirSelection"
                )

        if isinstance(mailbox, wayround_i2p.mail.server.directory.MailDir):
            mailbox = MailDirSelection(self, mailbox)

        self.mailbox_selection = mailbox

        return self.get_selection()

    def get_selection(self):
        return self.mailbox_selection

    def call_parse_parameters_sumarized(self, parameters_bytes):
        """
        this is shortcut for parse_parameters_sumarized, as it requires same
        objects each time, so to not bother with too many parameters
        """
        ret = wayround_i2p.mail.imap.parse_parameters_sumarized(
            parameters_bytes,
            self.lbl_reader,
            self.permanent_memory,
            self.accepted_socket,
            is_server=True,
            stop_event=self._stop_event
            )
        return ret

    def cmd_CAPABILITY(self, tag, cmd, parameters_bytes):

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
            ) + wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR

        response += wayround_i2p.mail.imap.s2c_response_format(
            line_parsed_tag,
            'OK',
            line_parsed_command + ' completed'
            )

        wayround_i2p.utils.socket.nb_sendall(
            self.accepted_socket,
            response
            )

        return

    def cmd_AUTHENTICATE(self, tag, cmd, parameters_bytes):

        ret = 0

        param_sum = self.call_parse_parameters_sumarized(parameters_bytes)

        self.session_logger.info(
            "client asked listing. params: {}".format(param_sum)
            )

        line_parsed_tag = tag
        line_parsed_command = cmd

        param0 = str(param_sum['strings'][0], 'utf-8')

        asked_method = param0.upper()

        if asked_method != 'PLAIN':
            wayround_i2p.utils.socket.nb_sendall(
                self.accepted_socket,
                wayround_i2p.mail.imap.s2c_response_format(
                    line_parsed_tag,
                    'BAD',
                    line_parsed_command
                    )
                )
            ret = 1

        if ret == 0:

            bad = False
            no = False

            sasl_session = wayround_i2p.sasl.sasl.init_mech('PLAIN', 'server')

            bad, no = self.server_authenticate(sasl_session, line_parsed_tag)

        if ret == 0:

            if bad and no:
                # TODO: log exception
                ret = 2

        if ret == 0:

            # TODO: log errors

            if bad:

                wayround_i2p.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_i2p.mail.imap.s2c_response_format(
                        line_parsed_tag,
                        'BAD',
                        line_parsed_command
                        )
                    )
                ret = 3

            if no:

                wayround_i2p.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_i2p.mail.imap.s2c_response_format(
                        line_parsed_tag,
                        'NO',
                        line_parsed_command
                        )
                    )
                ret = 4

        if ret == 0:

            sasl_session_authzid = sasl_session['authzid']
            sasl_session_authcid = sasl_session['authcid']
            sasl_session_passwd = sasl_session['passwd']

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

                self.user_obj = self.directory.get_user(
                    self.domain.cfg.domain,
                    sasl_session_authcid
                    )

                wayround_i2p.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_i2p.mail.imap.s2c_response_format(
                        line_parsed_tag,
                        'OK',
                        "authentication succeeded"
                        )
                    )

            elif auth_user_res == False:

                wayround_i2p.utils.socket.nb_sendall(
                    self.accepted_socket,
                    wayround_i2p.mail.imap.s2c_response_format(
                        line_parsed_tag,
                        'NO',
                        "authentication faliled"
                        )
                    )

            else:  # case of None, which should be not happen
                raise Exception("programming error")

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

                request += wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR

                wayround_i2p.utils.socket.nb_sendall(
                    self.accepted_socket,
                    request
                    )

                buf = self.lbl_reader.nb_get_next_line(
                    self._stop_event
                    )

                if (buf == wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR):
                    self.session_logger.error(
                        'connection closed by client unexpectedly'
                        )
                    break

                elif (buf == b'*'
                      + wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR):
                    self.session_logger.error(
                        'client wished to cancel authentication'
                        )
                    bad = True
                    break

            elif rcr[0] == 'ok':
                break

            else:
                break

            step += 1
        return bad, no

    def cmd_CREATE(self, tag, cmd, parameters_bytes):

        param_sum = self.call_parse_parameters_sumarized(parameters_bytes)

        self.session_logger.info(
            "client asked listing. params: {}".format(param_sum)
            )

        param0 = str(param_sum['strings'][0], 'utf-7')

        print("param0: {}".format(param0))

        mdr = self.user_obj.get_maildir_root()
        maildir = mdr.get_dir(param0)
        if maildir.create():
            wayround_i2p.utils.socket.nb_sendall(
                self.accepted_socket,
                wayround_i2p.mail.imap.s2c_response_format(
                    tag,
                    'OK',
                    "create completed"
                    )
                )
        else:
            wayround_i2p.utils.socket.nb_sendall(
                self.accepted_socket,
                wayround_i2p.mail.imap.s2c_response_format(
                    tag,
                    'NO',
                    "create failure: can't create mailbox with that name"
                    )
                )
        return

    def cmd_SELECT(self, tag, cmd, parameters_bytes):

        param_sum = self.call_parse_parameters_sumarized(parameters_bytes)

        self.session_logger.info(
            "client asked listing. params: {}".format(param_sum)
            )

        boxname = str(param_sum['strings'][0], 'utf-7')

        # MailDirSelection
        mdr = self.user_obj.get_maildir_root()
        mailbox = mdr.get_dir(boxname)
        selection = self.set_selection(mailbox)

        status_text = selection.render_status_text()

        wayround_i2p.utils.socket.nb_sendall(
            self.accepted_socket,
            status_text
            )

        wayround_i2p.utils.socket.nb_sendall(
            self.accepted_socket,
            wayround_i2p.mail.imap.s2c_response_format(
                tag,
                'OK',
                "SELECT Completed"
                )
            )
        return

    def cmd_LIST(self, tag, cmd, parameters_bytes):

        param_sum = self.call_parse_parameters_sumarized(parameters_bytes)

        self.session_logger.info(
            "client asked listing. params: {}".format(param_sum)
            )

        reference_name = str(param_sum['strings'][0], 'utf-7')

        mailbox_name = str(param_sum['strings'][1], 'utf-7')

        mdr = self.user_obj.get_maildir_root()
        # TODO: security checks needed here
        d = mdr.get_dir(reference_name)
        res = d.glob(mailbox_name)

        for i in res:
            result = (
                b'* ' +
                b'LIST () ' +
                b'"/" ' +
                b'"' +
                i.encode('utf-7') +
                b'"' +
                wayround_i2p.mail.miscs.STANDARD_LINE_TERMINATOR
                )

            wayround_i2p.utils.socket.nb_sendall(
                self.accepted_socket,
                result
                )

        wayround_i2p.utils.socket.nb_sendall(
            self.accepted_socket,
            wayround_i2p.mail.imap.s2c_response_format(
                tag,
                'OK',
                "LIST Completed"
                )
            )

        return

    def cmd_APPEND(self, tag, cmd, parameters_bytes):

        param_sum = self.call_parse_parameters_sumarized(parameters_bytes)

        self.session_logger.info(
            "client asked append. params: {}".format(param_sum)
            )

        mailbox = str(param_sum['strings'][0], 'utf-7')
        date = None
        if len(param_sum['strings']) > 1:
            date = wayround_i2p.utils.datetime_rfc5322.str_to_datetime(
                str(param_sum['strings'][1], 'utf-8')
                )

        pv = None
        if len(param_sum['strings']) > 2:
            pv = param_sum['strings'][2]
            if not isinstance(
                    pv,
                    wayround_i2p.utils.pm.PersistentVariable
                    ):
                raise Exception("TODO: here must be BAD error and normal exit")

        flags = param_sum['flags']

        mdr = self.user_obj.get_maildir_root()
        mailbox_obj = mdr.get_dir('/' + mailbox)
        msg = mailbox_obj.new_message()

        msg.import_data_from_persistent_variable(pv)

        msg.reindex(self._stop_event, self.session_logger)
        if flags is not None:
            msg.set_flags_by_list(flags)

        wayround_i2p.utils.socket.nb_sendall(
            self.accepted_socket,
            wayround_i2p.mail.imap.s2c_response_format(
                tag,
                'OK',
                "APPEND Completed"
                )
            )

        return


import threading
import os.path

import wayround_org.mail.server.server


class SpoolWorker:

    def __init__(
            self,
            server,
            interval_seconds=600  # 10 minutes
            ):

        if not isinstance(server, wayround_org.mail.server.server.Server):
            raise TypeError(
                "`server' must be inst of "
                "wayround_org.mail.server.server.Server"
                )

        if not isinstance(interval_seconds, int):
            raise TypeError("`interval_seconds' must be int")

        if interval_seconds < 1:
            raise ValueError("`interval_seconds' must be > 0")

        if interval_seconds > 3600:  # 1 hour TODO: need better limit. 1 Day?
            return ValueError("`interval_seconds' must be <= 3600")

        self.server = server
        self.directory = server.directory
        self.spool_dir = self.directory.get_spool_directory()

        # os.makedirs(self.spool_conversion_dir_path, exist_ok=True)

        self.interval_seconds = interval_seconds

        self._stop_event = threading.Event()
        self._stopped_event = threading.Event()

        self._worker_thread = None

        return

    def start(self):

        if self._worker_thread is None:
            self._stop_event.clear()
            self._stopped_event.clear()

            self._worker_thread = threading.Thread(
                target=self._worker_thread_target
                )

            self._worker_thread.start()

        return

    def stop(self):
        self._stop_event.set()
        self._stopped_event.wait()
        return

    def _worker_thread_target(self):

        while True:
            if self._stop_event.is_set():
                break

        self._worker_thread = None
        self._stopped_event.set()
        return

    def process_spool_element(self, name):

        ret = 0

        logger = self.directory.create_spool_logger(name)
        logger.info("started")

        logger.info("getting spool element named {}".format(name))

        element = self.spool_dir.get_element(name)
        i_have_locked_it = False

        if not element.get_is_exists():
            logger.error(
                "spool element with such name does not exists. exiting"
                )
            ret = 1

        if ret == 0:

            if element.get_is_locked():
                logger.error(
                    "this element is locked now. exiting"
                    )
                ret = 2

        if ret == 0:

            element.lock()
            i_have_locked_it = True

            logger.info(
                "I have locked this element now"
                " and going to work with it"
                )

            local_recps = []
            remote_recps = []

            logger.info("determining local routes of element")
            for i in element.get_to():

                mail_addr_obj = \
                    wayround_org.mail.miscs.Address.new_from_str(i)

                # TODO: correctness check. <- here or into directory.py

                domain = mail_addr_obj.authority.host
                user = mail_addr_obj.authority.userinfo.name

                del mail_addr_obj

                if self.directory.get_is_user_enabled(domain, user):
                    local_recps.append(
                        self.directory.get_user(
                            domain,
                            user
                            )
                        )
                else:
                    remote_recps.append(i)

            logger.info("result ({} item(s)):".format(len(local_recps)))
            for i in local_recps:
                logger.info(
                    "    {}@{}".format(
                        i.name,
                        i.domain_obj.domain
                        )
                    )

            for i in local_recps:
                mdr = i.get_maildir_root()
                inbox = mdr.get_dir('/INBOX')

                tm = self.spool_dir.get_transition_message(element.name)

                # NOTE: this can't be separated into thread, cause
                #       spooler still need to maintain element's flags
                tm.perform_transition(element, inbox)

        if i_have_locked_it:
            element.unlock()

        logger.stop()

        return

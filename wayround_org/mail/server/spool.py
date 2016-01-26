
import threading

import wayround_org.mail.server.server


class SpoolWorker:

    def __init__(
            self,
            server,
            interval_seconds=600  # 10 minutes
            ):

        if not isinstnace(server, wayround_org.mail.server.server.Server):
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

        element = self.spool_dir.get_element(name)
        i_have_locked_it = False

        if not element.get_is_exists():
            ret = 1
            # TODO: log this?

        if ret == 0:

            if element.get_is_locked():
                # TODO: log this?
                ret = 2

        if ret == 0:

            element.lock()
            i_have_locked_it = True

        if i_have_locked_it:
            element.unlock()

        return

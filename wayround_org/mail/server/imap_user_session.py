
import ssl


class IMAPUserSession:

    def __init__(self, login, sock):
        """

        if login is None then session is not autenticated
        """
        self.login = login
        self.sock = sock
        return

    def get_is_auth(self):
        return self.login is not None

    def get_is_ssl(self):
        return isinstance(self.sock, ssl.SSLSocket)

    def do_wrap_with_ssl(self):
        return

    def do_sasl_auth(self):
        return

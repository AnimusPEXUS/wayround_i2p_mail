

import sqlalchemy.ext.declarative
import sqlalchemy.orm


class MailServer(wayround_org.utils.db.BasicDB):

    def __init__(
            self,
            config_string=None,
            bind=None,
            decl_base=None,
            metadata=None
            ):

        super().__init__(
            config_string=config_string,
            bind=bind,
            decl_base=decl_base,
            metadata=metadata,
            init_table_data=None
            )

        return

    def init_table_mappings(self, init_table_data):

        class User(self.decl_base):

            __tablename__ = 'user'

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            password = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            disabled = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=False
                )
            

        self.User = User

        class Message(self.decl_base):

            __tablename__ = 'message'

            mid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            folder = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

        self.Message = Message

        return

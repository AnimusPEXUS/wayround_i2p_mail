
import collections

import wayround_org.mail.server.server


def commands():
    ret = collections.OrderedDict([
        ('server', collections.OrderedDict([
            ('run', server_run),
        ]))
    ])
    return ret


def server_run(command_name, opts, args, adds):
    ret = 0
    serv = wayround_org.mail.server.server.Server(
        #'/etc/wrows.conf'
        '/home/agu/tmp/test_mail_dir'
        )
    serv.start()
    serv.wait_for_shutdown()
    return ret

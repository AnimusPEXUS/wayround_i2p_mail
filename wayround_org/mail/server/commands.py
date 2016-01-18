

def commands():
    import collections

    ret = collections.OrderedDict([
        ('server', collections.OrderedDict([
            ('run', server_run),
        ])),

        ('dir', collections.OrderedDict([
            ('dom', collections.OrderedDict([
                ('list', dir_dom_list),
                ('list-enabled', dir_dom_list_enabled),
                ('list-disabled', dir_dom_list_disabled),
                ('create', dir_dom_create),
                ('enable', dir_dom_enable),
                ('disable', dir_dom_disable),
                ])),
            ('user', collections.OrderedDict([
                #('create', dir_user_create),
                #('enable', dir_user_enable),
                #('disable', dir_user_disable),
                #('passwd', dir_user_passwd),
                ])),
        ])),

    ])

    return ret


def server_run(command_name, opts, args, adds):

    import wayround_org.mail.server.server

    ret = 0
    serv = wayround_org.mail.server.server.Server(
        #'/etc/wrows.conf'
        '/home/agu/tmp/test_mail_dir'
        )
    serv.start()
    serv.wait_for_shutdown()
    return ret


def _load_directory():

    import wayround_org.mail.server.directory

    ret = wayround_org.mail.server.directory.RootDirectory(
        '/home/agu/tmp/test_mail_dir'
        )

    return ret


def print_output_list_items(lst):
    import wayround_org.utils.text
    txt = "[{} item(s)]".format(len(lst))
    line = '-' * len(txt)
    print(txt)
    print(line)
    print(wayround_org.utils.text.return_columned_list(lst))
    print(line)
    print(txt)
    return


def dir_dom_list(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 0:
        print("error: shold not be arguments")
        ret = 1

    if ret == 0:
        lst = directory.get_domain_list()
        print_output_list_items(lst)

    return ret


def dir_dom_list_enabled(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 0:
        print("error: shold not be arguments")
        ret = 1

    if ret == 0:
        lst = directory.get_enabled_domain_list()
        print_output_list_items(lst)

    return ret


def dir_dom_list_disabled(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 0:
        print("error: shold not be arguments")
        ret = 1

    if ret == 0:
        lst = directory.get_disabled_domain_list()
        print_output_list_items(lst)

    return ret


def dir_dom_create(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 1:
        print("error: one argument required")
        ret = 1

    if ret == 0:

        domain_name = args[0]

        d = directory.get_domain(domain_name)
        ret = d.create()

    return ret


def dir_dom_enable(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 1:
        print("error: one argument required")
        ret = 1

    if ret == 0:

        domain_name = args[0]

        d = directory.get_domain(domain_name)
        if not d.get_exists():
            print("error: can't enable non-existing domain. create it first")
            ret = 2

    if ret == 0:
        ret = d.set_enabled(True)

    return ret


def dir_dom_disable(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 1:
        print("error: one argument required")
        ret = 1

    if ret == 0:

        domain_name = args[0]

        d = directory.get_domain(domain_name)
        if not d.get_exists():
            print("error: can't disable non-existing domain. create it first")
            ret = 2

    if ret == 0:
        ret = d.set_enabled(False)

    return ret



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
                ('list', dir_user_list),
                #('list-enabled', dir_user_list_enabled),
                #('list-disabled', dir_user_list_disabled),
                ('create', dir_user_create),
                ('enable', dir_user_enable),
                ('disable', dir_user_disable),
                ('passwd', dir_user_passwd),
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
    print(wayround_org.utils.text.return_columned_list(lst), end='')
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
        d.create()

    return ret


def dir_dom_enable(command_name, opts, args, adds, value=True):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 1:
        print("error: one argument required")
        ret = 1

    if ret == 0:

        domain_name = args[0]

        d = directory.get_domain(domain_name)
        if not d.get_is_exists():
            print(
                "error: can't change `enabled' state on non-existing domain."
                " create it first"
                )
            ret = 2

    if ret == 0:
        d.set_is_enabled(value)

    return ret


def dir_dom_disable(command_name, opts, args, adds):
    return dir_dom_enable(command_name, opts, args, adds, False)


def normalize_domain_name_for_filesystem(domain_name):
    ret = domain_name
    ret = ret.strip().lower()
    return ret


def normalize_user_name_for_filesystem(user_name):
    ret = user_name
    ret = ret.strip().lower()
    return ret


def domain_exists_check(domain_object):

    ret = domain_object.get_is_exists()

    if not ret:
        print(
            "error: domain does not exists: {}".format(
                domain_object.path
                )
            )

    return ret


def user_exists_check(user_object):

    ret = user_object.get_is_exists()

    if not ret:
        print(
            "error: user does not exists: {}".format(
                user_object.path
                )
            )

    return ret


def dir_user_list(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 1:
        print("error: should be exactly one argument")
        ret = 1

    if ret == 0:
        domain_name = normalize_domain_name_for_filesystem(args[0])
        d = directory.get_domain(domain_name)

        if not domain_exists_check(d):
            ret = 2

    if ret == 0:
        lst = d.get_user_list()
        print_output_list_items(lst)

    return ret


def dir_user_create(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 2:
        print("error: two arguments required")
        ret = 1

    if ret == 0:

        domain_name = args[0]
        user_name = normalize_user_name_for_filesystem(args[1])

    if ret == 0:

        d = directory.get_domain(domain_name)
        u = d.get_user(user_name)

    if ret == 0:

        if not domain_exists_check(d):
            print("error: you need to create this domain first")
            ret = 2

    if ret == 0:
        u.create()

    return ret


def dir_user_enable(command_name, opts, args, adds, value=True):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 2:
        print("error: two arguments required")
        ret = 1

    if ret == 0:

        domain_name = args[0]
        user_name = normalize_user_name_for_filesystem(args[1])

    if ret == 0:

        d = directory.get_domain(domain_name)
        u = d.get_user(user_name)

    if ret == 0:

        if not domain_exists_check(d):
            print("error: you need to create this domain first")
            ret = 2

    if ret == 0:

        if not user_exists_check(u):
            print("error: you need to create this user first")
            ret = 3

    if ret == 0:
        u.set_is_enabled(value)

    return ret


def dir_user_disable(command_name, opts, args, adds):
    return dir_user_enable(command_name, opts, args, adds, False)

def dir_user_passwd(command_name, opts, args, adds):

    ret = 0

    directory = _load_directory()

    args_l = len(args)

    if args_l != 3:
        print("error: three arguments required")
        ret = 1

    if ret == 0:

        domain_name = normalize_domain_name_for_filesystem(args[0])
        user_name = normalize_user_name_for_filesystem(args[1])
        passwd = args[2]

    if ret == 0:

        d = directory.get_domain(domain_name)
        u = d.get_user(user_name)

    if ret == 0:

        if not domain_exists_check(d):
            print("error: you need to create this domain first")
            ret = 2

    if ret == 0:

        if not user_exists_check(u):
            print("error: you need to create this user first")
            ret = 3

    if ret == 0:
        u.set_password_data(passwd)

    return ret

#!/usr/bin/env python3

import argparse
import grp
import os
import pwd
import shutil
import subprocess
import sys
from glob import glob


USR_ROOT = os.path.join('/', 'usr', 'local')
VAR_ROOT = os.path.join('/', 'var', 'local')

ALWAYS_YES = False

AS_ROOT = False

NO_CONF = False

CTSUSER = 'contestrouser'


def copyfile(src, dest, owner, perm, group=None):
    shutil.copy(src, dest)
    owner_id = owner.pw_uid
    if group is not None:
        group_id = group.gr_gid
    else:
        group_id = owner.pw_gid
    os.chown(dest, owner_id, group_id)
    os.chmod(dest, perm)


def try_delete(path):
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError:
            print("[Warning] Skipping because directory is not empty: ", path)
    else:
        try:
            os.remove(path)
        except OSError:
            print("[Warning] File not found: ", path)


def makedir(dir_path, owner=None, perm=None):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    if perm is not None:
        os.chmod(dir_path, perm)
    if owner is not None:
        os.chown(dir_path, owner.pw_uid, owner.pw_gid)


def copytree(src_path, dest_path, owner, perm_files, perm_dirs):
    for path in glob(os.path.join(src_path, "*")):
        sub_dest = os.path.join(dest_path, os.path.basename(path))
        if os.path.isdir(path):
            makedir(sub_dest, owner, perm_dirs)
            copytree(path, sub_dest, owner, perm_files, perm_dirs)
        elif os.path.isfile(path):
            copyfile(path, sub_dest, owner, perm_files)
        else:
            print("Error: unexpected filetype for file %s. Not copied" % path)


def ask(message):
    return ALWAYS_YES or input(message) in ["Y", "y"]


def assert_root():
    if os.geteuid() != 0:
        print("[Error] You must be root to perform this action successfully. "
              "Try using 'sudo'.")
        exit(1)


def assert_not_root():
    if AS_ROOT:
        return

    if os.geteuid() == 0:
        print("[Error] You must not be root to perform this action "
              "successfully. Try not using 'sudo'.")
        exit(1)


def get_real_user():
    if AS_ROOT:
        return "root"

    name = os.getenv("SUDO_USER")
    if name is None:
        name = os.popen("logname").read().strip()

    if name == "root":
        print("[Error] You are logged in as root.")
        print(
            "[Error] Log in as a normal user instead, and use 'sudo' or 'su'.")
        exit(1)

    return name


def install_conf():
    assert_root()

    print("-> Copying configuration to /usr/local/etc/")
    root = pwd.getpwnam("root")
    ctsuser = pwd.getpwnam(CTSUSER)
    for conf_file_name in ["contestro.conf"]:
        conf_file = os.path.join(USR_ROOT, "etc", conf_file_name)

        if os.path.islink(conf_file):
            continue

        if os.path.exists(conf_file):
            if not ask("The %s file is already installed, type Y to overwrite "
                       "it: " % (conf_file_name)):
                continue
        if os.path.exists(os.path.join(".", "config", conf_file_name)):
            copyfile(os.path.join(".", "config", conf_file_name),
                     conf_file, ctsuser, 0o660)
        else:
            con_file_name = "%s.sample" % conf_file_name
            copyfile(os.path.join(".", "config", conf_file_name),
                     conf_file, ctsuser, 0o660)


def install():
    assert_root()

    real_user = get_real_user()

    try:
        ctsuser_gr = grp.getgrnam(CTSUSER)
    except KeyError:
        print("-> Creating group %s" % CTSUSER)
        subprocess.check_call(["groupadd", CTSUSER, "--system"])
        ctsuser_gr = grp.getgrnam(CTSUSER)

    try:
        ctsuser_pw = pwd.getpwnam(CTSUSER)
    except KeyError:
        print("-> Creating user %s" % CTSUSER)
        subprocess.check_call(["useradd", CTSUSER, "--system",
                               "--comment", "Contestro default user",
                               "--shell", "/bin/false", "--no-create-home",
                               "--no-user-group", "--gid", CTSUSER])
        ctsuser_pw = pwd.getpwnam(CTSUSER)

    root_pw = pwd.getpwnam("root")

    old_umask = os.umask(0o000)

    if not NO_CONF:
        install_conf()

    print("-> Creating directories")

    dirs = [os.path.join(VAR_ROOT, "log"),
            os.path.join(VAR_ROOT, "cache"),
            os.path.join(VAR_ROOT, "lib"),
            os.path.join(VAR_ROOT, "run"),
            os.path.join(VAR_ROOT, "include"),
            os.path.join(VAR_ROOT, "share")]

    for _dir in dirs:
        if os.path.islink(os.path.join(_dir, "contestro")):
            continue
        makedir(_dir, root_pw, 0o755)
        _dir = os.path.join(_dir, "contestro")
        makedir(_dir, ctsuser_pw, 0o770)

    if real_user != "root":
        print("-> Adding yourself to the %s group" % CTSUSER)
        if ask("Type Y if you want me to add \"%s\" to the %s group: "
               % (real_user, CTSUSER)):
            subprocess.check_call(["usermod", "-a", "-G", CTSUSER, real_user])
        else:
            print("### Remember to add yourself to the %s group to use"
                  "contestro: $ sudo usermod -a -G %s <user> ###"
                  % (CTSUSER, CTSUSER))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Manage prerequisites for Contestro"
    )

    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="All questions will be answer as yes"
    )
    parser.add_argument(
        "--no-conf", action="store_true",
        help="Don't install configuration files"
    )
    parser.add_argument(
        "-as-root", action="store_true",
        help="(DON'T USE) Allow running non-root commands as root"
    )
    parser.add_argument(
        "--ctsuser", action="store", type=str, default=CTSUSER,
        help="(DON'T USE) The user CTS will be run as"
    )

    subparser = parser.add_subparsers(metavar="command",
                                      help="Command to run")
    subparser.add_parser(
        "install",
        help="Install everything (root required)"
    ).set_defaults(func=install)

    args = parser.parse_args()

    ALWAYS_YES = args.yes
    NO_CONF = args.no_conf
    AS_ROOT = args.as_root
    CTSUSER = args.ctsuser

    if not hasattr(args, "func"):
        parser.error("No command was specified. Use --help for "
                     "more information.")

    args.func()

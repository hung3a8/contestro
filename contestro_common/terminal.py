import curses
import sys


class colors:
    BLACK = curses.COLOR_BLACK
    RED = curses.COLOR_RED
    GREEN = curses.COLOR_GREEN
    YELLOW = curses.COLOR_YELLOW
    BLUE = curses.COLOR_BLUE
    MAGENTA = curses.COLOR_MAGENTA
    CYAN = curses.COLOR_CYAN
    WHITE = curses.COLOR_WHITE


class directions:
    UP = 1
    DOWN = 2
    LEFT = 3
    RIGHT = 4


def has_color_support(stream):
    if stream.isatty():
        try:
            curses.setupterm(fd=stream.fileno())
            # See `man terminfo` for capabilities' names and meanings.
            if curses.tigetnum("colors") > 0:
                return True
        # fileno() can raise OSError.
        except Exception:
            pass
    return False


def add_color_to_string(string, color, stream=sys.stdout, bold=False,
                        force=False):
    if force or has_color_support(stream):
        return "%s%s%s%s" % (
            curses.tparm(curses.tigetstr("setaf"), color).decode('ascii')
            if color != colors.BLACK else "",
            curses.tparm(curses.tigetstr("bold")).decode('ascii')
            if bold else "",
            string,
            curses.tparm(curses.tigetstr("sgr0")).decode('ascii')
        )
    else:
        return string


def move_cursor(direction, amount=1, stream=sys.stdout, erase=False):
    if stream.isatty():
        if direction == directions.UP:
            print(curses.tparm(curses.tigetstr("cuu"), amount).decode('ascii'),
                  file=stream, end='')
        elif direction == directions.DOWN:
            print(curses.tparm(curses.tigetstr("cud"), amount).decode('ascii'),
                  file=stream, end='')
        elif direction == directions.LEFT:
            print(curses.tparm(curses.tigetstr("cub"), amount).decode('ascii'),
                  file=stream, end='')
        elif direction == directions.RIGHT:
            print(curses.tparm(curses.tigetstr("cuf"), amount).decode('ascii'),
                  file=stream, end='')
        if erase:
            print(curses.tparm(curses.tigetstr("el")).decode('ascii'),
                  file=stream, end='')
        stream.flush()
class bcolors:
    """
    Class defining ANSI escape codes for colored terminal output.
    """
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def header(message, newline=False):
    """
    Display a bold header message in the terminal.

    Args:
        message (str): The header message.
        newline (bool, optional): Whether to add a newline after the header. Defaults to False.
    """
    print(bcolors.BOLD + message + bcolors.ENDC)
    if newline:
        print('\n')

def log(message, variable='', newline=False, freq=1):
    """
    Display log messages in the terminal.

    Args:
        message (str): The log message.
        variable (str, optional): Additional information or variables to display. Defaults to an empty string.
        newline (bool, optional): Whether to add a newline after the log message. Defaults to False.
        freq (int, optional): The frequency of repetitions. Defaults to 1.
    """
    for i in range(freq):
        print(message, variable)
    if newline:
        print('\n')

def error(message, variable='', newline=False, freq=1):
    """
    Display error messages in the terminal with a warning color.

    Args:
        message (str): The error message.
        variable (str, optional): Additional information or variables to display. Defaults to an empty string.
        newline (bool, optional): Whether to add a newline after the error message. Defaults to False.
        freq (int, optional): The frequency of repetitions. Defaults to 1.
    """
    for i in range(freq):
        print(bcolors.WARNING + message + bcolors.ENDC, variable)
    if newline:
        print('\n')

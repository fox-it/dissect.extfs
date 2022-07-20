class Error(Exception):
    pass


class FileNotFoundError(Error):
    pass


class NotADirectoryError(Error):
    pass


class NotASymlinkError(Error):
    pass

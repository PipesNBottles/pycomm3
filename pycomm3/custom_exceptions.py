class PycommError(Exception):
    ...


class CommError(PycommError):
    ...


class DataError(PycommError):
    ...


class RequestError(PycommError):
    ...
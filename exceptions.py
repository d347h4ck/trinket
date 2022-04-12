class CrudException(Exception):
    code: int
    reason: str

    def __init__(self, code, reason):
        self.code = code
        self.reason = reason

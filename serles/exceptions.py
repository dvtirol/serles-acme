class ACMEError(Exception):
    """
    Raise this exception on invalid API usage. The exception handler will
    return an Error Document to the client.

    Args:
        message (str): returned to client as the "detail" field.
        status (int): HTTP status code for the response.
        error_type (str): type token from the ACME namespace.
    """

    def __init__(self, message, status, error_type):
        super().__init__(message)
        self.status = status
        self.error_type = error_type

# customErrors.py
# these classes represent the various custom errors
# Exact copy of the CSAO remediation codebase's customErrors — reused
# as-is per instruction, even though this scanner currently only raises
# GenericError. Kept here so future AI Inventory error handling can adopt
# the same typed-error pattern the remediation side already uses.


class GenericError(Exception):
    """
    Exception raised for generic/unknown errors that occur anywhere within
    the lifecycle of the event.

    Attributes:
        errorCode -- status code for the error caught
        error -- error caught
        errorMessage -- explanation of the error
    """

    def __init__(self, errorCode, error, errorMessage):
        self.errorCode = errorCode
        self.error = error
        self.errorMessage = errorMessage


# Not required for now
class RequestError(Exception):
    """
    Exception raised for errors in the Request.

    Attributes:
        errorCode -- status code for the error caught
        error -- error caught
        errorMessage -- explanation of the error
    """

    def __init__(self, errorCode, error, errorMessage):
        self.errorCode = errorCode
        self.error = error
        self.errorMessage = errorMessage


class StepError(Exception):
    """
    Exception raised for errors in the Step functions.
    """
    pass


class InputError(Exception):
    """
    Exception raised for errors in the Data Input.

    Attributes:
        errorCode -- status code for the error caught
        error -- error caught
        errorMessage -- explanation of the error
    """

    def __init__(self, errorCode, error, errorMessage):
        self.errorCode = errorCode
        self.error = error
        self.errorMessage = errorMessage


class ScanRequestError(Exception):
    """
    Exception raised for error in scan step function in VSA
    Attributes:
        errorCode -- status code for the error caught
        errorMessage -- explanation of the error
    """

    def __init__(self, errorMessage, errorCode):
        self.errorMessage = errorMessage
        self.errorCode = errorCode


class AuthError(Exception):
    """
    Exception raised for errors in the Authorisation.

    Attributes:
        errorCode -- status code for the error caught
        error -- error caught
        errorMessage -- explanation of the error
    """

    def __init__(self, errorCode, error, errorMessage):
        self.errorCode = errorCode
        self.error = error
        self.errorMessage = errorMessage


class ValidationError(Exception):
    """
    Exception raised for errors during the JSON Validation.

    Attributes:
        errorCode -- status code for the error caught
        error -- error caught
        errorMessage -- explanation of the error
    """

    def __init__(self, errorCode, error, errorMessage):
        self.errorCode = errorCode
        self.error = error
        self.errorMessage = errorMessage


class InvalidAuthorizationToken(Exception):
    """
    Exception raised for errors in the Authorization Token.

    Attributes:
        details -- details of the error that occured
    """

    def __init__(self, details):
        super().__init__(f'Invalid authorization token: {details}')

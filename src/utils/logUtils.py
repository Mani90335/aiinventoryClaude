"""
logUtils.py

This file holds the wrapper around the python library "logging"
"""
# Standard imports
import os
import sys
import logging
from inspect import getframeinfo, stack

logging.basicConfig(format='[%(filename)s:%(lineno)d] %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get("logLevel", "DEBUG")))

# This function normalizes all log errors to a standard format
# it includes the MODULE that called the logger (i.e., the py file that made the call)


def logError(module, error):
    caller = getframeinfo(stack()[1][0])
    if hasattr(error, 'error') and hasattr(error, 'errorMessage'):
        errorMessage = f"Caught exception in line number {caller.lineno} from module: {module}\nError Code: {error.errorCode} \nError: {error.error} \nError Message: {error.errorMessage}"
    else:
        errorMessage = f"Caught exception in line number {caller.lineno} from module: {module}\nError Message: {str(error)}"
    logger.error(errorMessage)

# This function normalizes all log info to a standard format
# it includes the MODULE that called the logger (i.e., the py file that made the call)


def logInfo(module, info):
    Message = f"Logging from module: {module}\n Message: {info}"
    logger.info(Message)

# This function normalizes all debug logs to a standard format
# it includes the MODULE that called the logger (i.e., the py file that made the call)


def logDebug(module, info):
    caller = getframeinfo(stack()[1][0])
    Message = f"Logging from line number {caller.lineno} and module: {module}\n Message: {info}"
    logger.debug(Message)

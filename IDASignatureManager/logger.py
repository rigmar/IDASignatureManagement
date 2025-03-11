import logging
import os

from IDASignatureManager.utils import user_resource

_loggers = {}
level = "TRACE"

def start_logging(log_path, log_name, level):
    """
    Setup the logger: add a new log level, create a logger which logs into
    the console and also into a log files located at: logs/idarling.%pid%.log.
    """
    global _loggers

    if log_name in _loggers:
        return _loggers[log_name]

    # Add a new log level called TRACE, and more verbose that DEBUG.
    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, "TRACE")
    logging.Logger.trace = lambda inst, msg, *args, **kwargs: inst.log(
        logging.TRACE, msg, *args, **kwargs
    )
    logging.trace = lambda msg, *args, **kwargs: logging.log(
        logging.TRACE, msg, *args, **kwargs
    )

    logger = logging.getLogger(log_name)
    if level != None:
        if not isinstance(level, int):
            level = getattr(logging, level)
        logger.setLevel(level)

    # Log to the console with a first format
    logger.propagate = False # avoid having 2 log lines
    stream_handler = logging.StreamHandler()
    log_format = "[IdaDatabaseMerger][%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Log to the disk with a second format
    file_handler = logging.FileHandler(log_path)
    log_format = "[%(asctime)s][%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format, datefmt="%H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    _loggers[log_name] = logger
    return logger

logger_instance = start_logging(user_resource("logs","ida_database_merger.%s.log" % os.getpid()),"IdaDatabaseMerger.Plugin",level)
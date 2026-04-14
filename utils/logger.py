import logging
import os
import sys


def setup_logger():
    os.makedirs("output", exist_ok=True)

    log = logging.getLogger("security_pipeline")
    log.setLevel(logging.INFO)

    # Avoid duplicate handlers if this module is imported multiple times.
    if log.handlers:
        return log

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler("output/engine.log")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    log.addHandler(file_handler)
    log.addHandler(stream_handler)
    log.propagate = False

    return log


logger = setup_logger()

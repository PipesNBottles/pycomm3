import logging

from typing import List, Tuple, Optional, Union

class Packet:
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())


DataFormatType = List[Tuple[Optional[str], Union[str, int]]]
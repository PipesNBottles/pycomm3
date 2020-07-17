from typing import NamedTuple, Any, Optional
from reprlib import repr as _r

import logging

class Tag(NamedTuple):

    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())

    tag: str
    value: Any
    type: Optional[str] = None
    error: Optional[str] = None

    def __bool__(self):
        return self.value is not None and self.error is None

    def __str__(self):
        return f'{self.tag}, {_r(self.value)}, {self.type}, {self.error}'

    def __repr__(self):
        return f"{self.__class__.__name__}(tag={self.tag!r}, value={self.value!r}, type={self.type!r}, error={self.error!r})"
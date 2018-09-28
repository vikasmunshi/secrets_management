#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Registration Authority """
from typing import Callable

__all__ = (
    'allowed_unvalidated',
    'not_allowed',
    'validated',
)

allowed_unvalidated = True
not_allowed = False


def validated(validation_func: Callable[[str], bool], value: str) -> bool:
    return validation_func(value)

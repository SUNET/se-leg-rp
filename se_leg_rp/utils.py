# -*- coding: utf-8 -*-

from uuid import uuid4


def get_unique_hash():
    return str(uuid4())


def get_short_hash(entropy=10):
    return uuid4().hex[:entropy]

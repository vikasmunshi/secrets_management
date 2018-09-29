#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" file io local / url """
from functools import lru_cache
from json import dump, dumps, load, loads
from os import path
from ssl import SSLContext
from urllib import parse, request
from uuid import uuid4

__all__ = (
    'read_file_or_url',
    'write_file_or_url',
)


def _append_req_id_to_url(url: str) -> str:
    components = list(parse.urlparse(url))
    components[4] = parse.urlencode(parse.parse_qsl(components[4]) + [('req_id', str(uuid4()))])
    return parse.urlunparse(components)


@lru_cache()
def _get_simple_context() -> SSLContext:
    ca_file = path.join(path.abspath(path.dirname(__file__)), 'ca.pem')
    context = SSLContext()
    context.load_verify_locations(cafile=ca_file)
    return context


def _is_url(name: str) -> bool:
    return name.startswith('https://')


def read_file_or_url(file_url: str) -> dict:
    if _is_url(file_url):
        return loads(request.urlopen(
            url=request.Request(
                url=_append_req_id_to_url(url=file_url),
                headers={'Accept': 'application/json', 'charset': 'utf-8'},
                method='GET'),
            context=_get_simple_context()).read())
    else:
        with open(file_url) as infile:
            return load(infile)


def write_file_or_url(dict_obj: dict, file_url: str) -> None:
    if _is_url(file_url):
        data_bytes = dumps(dict_obj).encode()
        request.urlopen(
            url=request.Request(
                url=_append_req_id_to_url(url=file_url),
                data=data_bytes,
                headers={'Content-Type': 'application/json', 'charset': 'utf-8', 'Content-Length': len(data_bytes)},
                method='POST'
            ),
            context=_get_simple_context())
    else:
        with open(file_url, 'w') as outfile:
            dump(obj=dict_obj, fp=outfile, indent=2)

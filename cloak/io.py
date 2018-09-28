#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" file io local / url """
from functools import lru_cache
from json import dump, dumps, load, loads
from os import path
from ssl import SSLContext
from urllib import request
from uuid import uuid4

__all__ = (
    'read_file_url',
    'write_file_url',
)


@lru_cache()
def _get_simple_context() -> SSLContext:
    ca_file = path.join(path.abspath(path.dirname(__file__)), 'ca.pem')
    context = SSLContext()
    context.load_verify_locations(cafile=ca_file)
    return context


def _is_url(name: str) -> bool:
    return name.lower().startswith('https')


def read_file_url(file_url: str) -> dict:
    if _is_url(file_url):
        return loads(request.urlopen(
            url=request.Request(
                url=file_url + '?req_id={}'.format(uuid4()),
                headers={'Accept': 'application/json', 'charset': 'utf-8'},
                method='GET'),
            context=_get_simple_context()).read())
    else:
        with open(file_url) as infile:
            return load(infile)


def write_file_url(dict_obj: dict, file_url: str) -> None:
    if _is_url(file_url):
        data_bytes = dumps(dict_obj).encode()
        response = request.urlopen(
            url=request.Request(
                url=file_url,
                data=data_bytes,
                headers={'Content-Type': 'application/json', 'charset': 'utf-8', 'Content-Length': len(data_bytes)},
                method='POST'
            ),
            context=_get_simple_context())
        if not 200 <= response.status < 300:
            raise IOError('')
    else:
        with open(file_url, 'w') as outfile:
            dump(obj=dict_obj, fp=outfile, indent=2)

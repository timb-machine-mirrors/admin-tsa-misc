#!/usr/bin/python3
# coding: utf-8

'''minimalist KGB python client'''
# Copyright (C) 2020 Antoine Beaupré <anarcat@debian.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import hashlib
import json
import logging
import os

import requests

from . import hash_digest_hex


def relay_message(message, url, session=None, repo_id=None, password=None):
    '''relay an arbitrary message to a KGB bot URL

    The URL should *not* have a trailing slash, a /json-rpc string
    will be appended.
    '''
    if session is None:
        session = requests.Session()
    if repo_id is None:
        repo_id = os.environ.get("HTTP_USER", "")
        if not repo_id:
            logging.warning(
                "repo_id is empty, provide it through the HTTP_USER environment"
            )
    if password is None:
        password = os.environ.get("HTTP_PASSWORD", "")
        if not password:
            logging.warning(
                "password is empty, provide it through the HTTP_PASSWORD environment"
            )
    # most of the stuff here is from the kgb-protocol(7) manpage and
    # some static analysis of the App/KGB/Client/ServerRef.pm source
    # code, particularly the send_changes_json function
    payload = json.dumps({
        "method": "relay_message",
        "params": [message],
        "version": '1.1',
        # arbitrarily picked, but should vary if we expect async
        # responses to match, which is not currently the case
        "id": 1,
    })
    # from the kgb-protocol(7) manpage: the auth header is the
    # password, repo id and payload concatenated...
    to_hash = password + repo_id + payload
    # ... and SHA-1 hashed in hex (no : delimiter)
    header_auth = hash_digest_hex(to_hash.encode('utf-8'), hash=hashlib.sha1, sep=b'')
    # setup the JSON-RPC headers along with the auth header and the repo id
    headers = {
        'content-type': 'application/json',
        'X-KGB-Auth': header_auth,
        'X-KGB-Project': repo_id,
    }
    logging.debug('sending request: %s, headers: %s', payload, headers)
    # deliver the payload to the host
    response = session.post(url + '/json-rpc', data=payload, headers=headers)
    success = response.ok and response.json()['result'] == 'OK'
    logging.debug('response: %s, %s, success: %s', response, response.json(), success)
    return success


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s", level="DEBUG")
    relay_message('anarcat test', 'https://kgb-bot.torproject.org')

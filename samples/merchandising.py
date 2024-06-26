# -*- coding: utf-8 -*-
"""
Copyright 2012-2019 eBay Inc.
Authored by: Tim Keefer
Licensed under CDDL 1.0
"""

import os
import sys
from optparse import OptionParser

sys.path.insert(0, "%s/../" % os.path.dirname(__file__))

from common import dump

from ebaysdk.exception import ConnectionError
from ebaysdk.merchandising import Connection as merchandising


def init_options():
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)

    parser.add_option(
        "-d",
        "--debug",
        action="store_true",
        dest="debug",
        default=False,
        help="Enabled debugging [default: %default]",
    )
    parser.add_option(
        "-y",
        "--yaml",
        dest="yaml",
        default="ebay.yaml",
        help="Specifies the name of the YAML defaults file. [default: %default]",
    )
    parser.add_option(
        "-a",
        "--appid",
        dest="appid",
        default=None,
        help="Specifies the eBay application id to use.",
    )
    parser.add_option(
        "-n",
        "--domain",
        dest="domain",
        default="svcs.ebay.com",
        help="Specifies the eBay domain to use (e.g. svcs.sandbox.ebay.com).",
    )

    (opts, args) = parser.parse_args()
    return opts, args


def run(opts):
    try:
        api = merchandising(
            debug=opts.debug,
            appid=opts.appid,
            domain=opts.domain,
            config_file=opts.yaml,
            warnings=True,
        )

        response = api.execute("getMostWatchedItems", {"maxResults": 4})

        dump(api)
    except ConnectionError as e:
        print(e)
        print(e.response.dict())


if __name__ == "__main__":
    (opts, args) = init_options()
    run(opts)

# -*- coding: utf-8 -*-
"""
Copyright 2012-2019 eBay Inc.
Authored by: Tim Keefer
Licensed under CDDL 1.0
"""

from ebaysdk.poller import parse_args
from ebaysdk.poller.orders import Poller


class CustomStorage(object):
    def set(self, order):
        try:
            print(order.OrderID)
            print(order.OrderStatus)
            print(order.SellerEmail)

            for txn in order.TransactionArray.Transaction:
                print("%s: %s" % (txn.TransactionID, txn.Item.Title))

        except Exception:
            pass
            # from IPython import embed; embed()


if __name__ == "__main__":
    (opts, args) = parse_args("usage: python -m samples.poller [options]")

    poller = Poller(opts, CustomStorage())
    poller.run()

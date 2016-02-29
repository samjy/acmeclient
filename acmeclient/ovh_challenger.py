#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import re
import logging

import ovh

from challengers import Dns01Challenger

logger = logging.getLogger(__name__)


def get_ovh_client(key, secret, consumer):
    """Get an ovh client
    """
    client = ovh.Client(
            endpoint='ovh-eu',
            application_key=key,
            application_secret=secret,
            consumer_key=consumer,
    )
    return client


def get_consumer_key(key, secret):
    """Handles the process to get a consumer key
    """
    # create a client using configuration
    client = get_ovh_client(key, secret, None)

    # Request RO, /me API access
    access_rules = [
        {'method': 'GET', 'path': '/me'},
        {'method': 'GET', 'path': '/domain/*'},
        {'method': 'POST', 'path': '/domain/*'},
        {'method': 'PUT', 'path': '/domain/*'},
        {'method': 'DELETE', 'path': '/domain/*'}
    ]

    # Request token
    validation = client.request_consumerkey(access_rules)

    print "Please visit %s to authenticate" % validation['validationUrl']
    raw_input("and press Enter to continue...")

    # Print nice welcome message
    print "Welcome", client.get('/me')['firstname']
    print "Btw, your 'consumerKey' is '%s'" % validation['consumerKey']


def set_record(client, domain, selector, data):
    """Creates a new record

    :returns: (int) The id of the created record
    """
    # create a new record
    record = {
        'fieldType': 'TXT',
        'subDomain': selector,
        'target': data,
        'ttl': 60,  # 1 min (minimum allowed by OVH)
    }
    ret = client.post('/domain/zone/%s/record' % domain, **record)
    # refresh the zone
    client.post('/domain/zone/%s/refresh' % domain)
    # return id
    return ret['id']


class OVHDns01Challenger(Dns01Challenger):
    """Satisfies dns01 challenges using OVH api
    """

    def __init__(self, config):
        """Initializes, creates ovh client
        """
        super(OVHDns01Challenger, self).__init__(config)
        self.created = {}
        self.ovh_client = get_ovh_client(config['OVH_APP_KEY'],
                                         config['OVH_SECRET_KEY'],
                                         config['OVH_CONSUMER_KEY'])

    def accomplish(self, domain, challb, validation):
        """Accomplish the challenge
        """
        fulldomain = challb.validation_domain_name(domain)
        logger.info("Domain %s: setting DNS", domain)
        logger.debug("  challenge DNS domain: %s", fulldomain)
        logger.debug("  challenge value: %s", validation)
        selector, root_name, tld_name = fulldomain.rsplit('.', 2)
        root_domain = "%s.%s" % (root_name, tld_name)
        _id = set_record(self.ovh_client, root_domain, selector, validation)
        if not _id:
            raise Exception("Didn't manage to set record")
        self.created.setdefault(root_domain, []).append(_id)
        logger.debug("  done.")

    def cleanup(self):
        """Cleanup: remove entries created for ``accomplish``
        """
        logger.info("Cleaning up")
        for domain, _ids in self.created.items():
            for _id in _ids:
                self.ovh_client.delete(
                    '/domain/zone/%s/record/%s' % (domain, _id))

        logger.debug("  done.")


if __name__ == '__main__':
    import yaml
    filename = sys.argv[1]
    config = yaml.load(open(filename, 'r').read())
    get_consumer_key(config['OVH_APP_KEY'], config['OVH_SECRET_KEY'])

# EOF

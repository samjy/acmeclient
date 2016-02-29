#!/usr/bin/env python
# -*- coding: utf-8 -*-


import time
import importlib
import logging

import acme.challenges
from tabulate import tabulate

import challenges
from utils import Challenger

logger = logging.getLogger(__name__)


def import_challenger(name):
    """Imports the challenger from given module.class
    """
    fullmodule, classname = name.rsplit('.', 1)
    package = None
    modulename = None
    if '.' in fullmodule:
        package, modulename = fullmodule.rsplit('.', 1)
    else:
        modulename = fullmodule

    module = importlib.import_module(modulename, package=package)
    return getattr(module, classname)


class Http01Challenger(Challenger):
    """Satisfies http01 challenges
    """

    challenge_type = acme.challenges.HTTP01

    def accomplish(self, domain, challb, validation):
        """Accomplish the challenge
        """
        logger.info("Domain %s", domain)
        logger.debug("  challenge path: %s", challb.path)
        logger.debug("  challenge value: %s", validation)
        # TODO

    def cleanup(self):
        """Clean up
        """
        logger.info("Cleaning up")
        # TODO


class ManualHttp01Challenger(Http01Challenger):
    """Satisfies http01 challenges

    Manual file creation
    """


class MultiServerHttp01Challenger(Http01Challenger):
    """Satisfies http01 challenges for domains deployed on multiple servers
    """

    challenge_type = acme.challenges.HTTP01

    def accomplish(self, domain, challb, validation):
        """Accomplish the challenge
        """
        logger.info("Domain %s", domain)
        logger.debug("  challenge path: %s", challb.path)
        logger.debug("  challenge value: %s", validation)
        # TODO

    def cleanup(self):
        """Clean up
        """
        logger.info("Cleaning up")
        # TODO


class Dns01Challenger(Challenger):
    """Satisfies dns01 challenges

    Allow manual DNS edition
    """

    challenge_type = challenges.DNS01

    def __init__(self, config):
        """Initialize
        """
        super(Dns01Challenger, self).__init__(config)
        self.all_entries = []

    def accomplish(self, domain, challb, validation):
        """Accomplish the challenge
        """
        fulldomain = challb.validation_domain_name(domain)
        logger.info("Domain %s", domain)
        logger.debug("  challenge DNS domain: %s", fulldomain)
        logger.debug("  challenge value: %s", validation)

        # TODO this is incomplete (e.g. www.example.co.uk)
        # TODO maybe we need to pass root_domain in conf?
        selector, root_name, tld_name = fulldomain.rsplit('.', 2)
        root_domain = "%s.%s" % (root_name, tld_name)
        print ("Please create the following DNS TXT record "
               "in zone %s:") % root_domain
        entry = [selector, '60', 'IN', 'TXT', '"%s"' % validation]
        self.all_entries.append([root_domain] + entry)
        print tabulate([entry],
                       ['name', 'ttl', 'class', 'rr', 'text'],
                       tablefmt="plain")
        raw_input("Press Enter when done")

    def all_accomplished(self):
        """Once all challenges are completed, wait 1 min for DNS to propagate
        """
        logger.info("Waiting 1 min for DNS expiry")
        for i in range(3):
            logger.info("  %d sec remaining", (60 - 20 * i))
            time.sleep(20)

    def cleanup(self):
        """Clean up
        """
        logger.info("Cleaning up")
        print "You can now delete the following DNS records:"
        print tabulate(self.all_entries,
                       ['zone', 'name', 'ttl', 'class', 'rr', 'text'],
                       tablefmt="simple")
        raw_input("Press Enter when done")


# EOF

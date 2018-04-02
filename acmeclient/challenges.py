#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import base64
import re
import logging

import dns.resolver
import josepy as jose
import acme.challenges
import time

logger = logging.getLogger(__name__)


def nopadding(s):
    return re.sub('=*$', '', s)


DNS_SERVERS = [
    # google
    '8.8.8.8',
    '8.8.4.4',
]


@acme.challenges.ChallengeResponse.register
class DNS01Response(acme.challenges.KeyAuthorizationChallengeResponse):
    typ = "dns-01"

    validation = jose.Field("validation", decoder=jose.JWS.from_json)

    def simple_verify(self, chall, domain, account_public_key, **unused_kwargs):
        """Simple verify.
        """
        # get a dns resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = DNS_SERVERS

        signature = nopadding(base64.urlsafe_b64encode(hashlib.sha256(
            self.key_authorization
        ).digest()))
        logger.info("Domain %s: looking for %s", domain, signature)
        for i in range(10):
            # keep looping to get refreshed DNS values
            dns_results = resolver.query(
                chall.validation_domain_name(domain),
                'TXT',
            )
            for rdata in dns_results:
                val = ''.join(rdata.strings)
                logger.debug("  TXT %s", val)
                if signature in val:
                    logger.debug("ok")
                    return True

            wait_time = 2 ** i
            logger.debug("Sleeping %s sec", wait_time)
            time.sleep(wait_time)

    def check_validation(self, chall, account_public_key):
        """Check validation.
        """
        return chall.check_validation(self.validation, account_public_key)


@acme.challenges.Challenge.register
class DNS01(acme.challenges.KeyAuthorizationChallenge):
    response_cls = DNS01Response
    typ = response_cls.typ
    LABEL = "_acme-challenge"

    def validation(self, account_key, **kwargs):
        """Validation
        """
        return nopadding(base64.urlsafe_b64encode(hashlib.sha256(
            self.key_authorization(account_key)
        ).digest()))

    def validation_domain_name(self, name):
        """Domain name for TXT validation record.
        """
        return "{0}.{1}".format(self.LABEL, name)


# EOF

#!/usr/bin/env python
# -*- coding: utf-8 -*-


import datetime
import hashlib
import logging

from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL
import requests
import pytz
import acme.jose
import acme.client
import acme.messages
import letsencrypt.crypto_util as crypto_util

ACME_SERVER_STAGING = 'https://acme-staging.api.letsencrypt.org/directory'
ACME_SERVER_PROD = 'https://acme-v01.api.letsencrypt.org/directory'
DEFAULT_TOS_SHA256 = ('33d233c8ab558ba6c8ebc370a509a'
                      'cdded8b80e5d587aa5d192193f35226540f')

logger = logging.getLogger(__name__)


def generate_private_key(key_size=4096):
    """Generate a private key.
    """
    if key_size < 1024:
        raise ValueError("Key is too small!")

    return crypto_util.make_key(key_size)


def generate_client_key(key_size=4096, public_exponent=65537):
    """Generate a client key
    """
    return acme.jose.JWKRSA(key=rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend(),
    ))


def generate_csr(private_key, *domains):
    """Generate certificate signing request
    """
    pem, der = crypto_util.make_csr(private_key, domains)
    return pem, der


def get_acme_client(key,
                    server=ACME_SERVER_STAGING,
                    user_agent=None):
    """Register an account
    """
    net = acme.client.ClientNetwork(key, user_agent=user_agent)
    client = acme.client.Client(directory=server, key=key, net=net)
    return client


def sha256_of_uri_contents(uri, chunk_size=10):
    """Get SHA256 of URI contents.
    """
    h = hashlib.sha256()
    response = requests.get(uri, stream=True)
    for chunk in response.iter_content(chunk_size):
        h.update(chunk)
    return h.hexdigest()


def register_client(client, email=None):
    """Register the given client
    """
    new_reg = acme.messages.NewRegistration.from_data(email=email)
    try:
        # register account
        regr = client.register(new_reg)
    except acme.messages.Error as error:
        if error.detail != 'Registration key is already in use':
            raise
    else:
        # agree to terms of service if needed
        if regr.terms_of_service is not None:
            tos_hash = sha256_of_uri_contents(regr.terms_of_service)
            logger.debug('TOS hash: %s', tos_hash)
            # TODO is tos_hash always the same?
            # if no, we should maybe store it somewhere?
            if tos_hash != DEFAULT_TOS_SHA256:
                raise RuntimeError('TOS hash mismatch. Found: %s.' % tos_hash)
            client.agree_to_tos(regr)

    return client


def get_authorization(client, domain):
    """Get autorization object
    """
    return client.request_domain_challenges(
        domain, new_authz_uri=client.directory.new_authz)


def get_challenge(authorization, challenge_type=None):
    """Get a challenge of given type for the authorization

    :param authorization: acme.messages.AuthorizationResource
    :param challenge_type: acme.challenges.HTTP01
    """
    if challenge_type is None:
        raise ValueError("A challenge_type is needed")

    for combo in authorization.body.combinations:
        if len(combo) != 1:
            continue

        first_challb = authorization.body.challenges[combo[0]]
        if isinstance(first_challb.chall, challenge_type):
            return first_challb

    raise ValueError("No such challenge %s" % challenge_type)


class Challenger(object):
    """An object which can accomplish the challenge
    """

    challenge_type = None

    def __init__(self, config):
        """Initialize with config
        """
        self.config = config

    def accomplish(self, domain, chall, validation):
        """Accomplish the challenge

        Everything done here should be cleaned up afterwards, so keep a track
        of what is done... (see ``cleanup``)
        """
        raise NotImplementedError("Do it")

    def all_accomplished(self):
        """Possible action after challenger accomplished all challenges
        """
        # default is to do nothing
        return

    def cleanup(self):
        """Cleans up everything that it made

        This can have been tracked while accomplishing
        """
        raise NotImplementedError("Do it")


def answer_challenges(client, challenger, *domains):
    """Answer the challenges for all domains
    """
    authorizations = []
    all_challenges = []

    # first setup all challenges
    logger.info("Setting up challenges")
    for domain in domains:
        authorization = get_authorization(client, domain)
        authorizations.append(authorization)
        challb = get_challenge(authorization,
                               challenge_type=challenger.challenge_type)
        response, validation = challb.response_and_validation(client.key)
        challenger.accomplish(domain, challb, validation)

        all_challenges.append({
            'authorization': authorization,
            'response': response,
            'challb': challb,
            'domain': domain,
        })

    challenger.all_accomplished()

    # then verify all responses
    logger.info("Verify all responses")
    for item in all_challenges:
        verified = item['response'].simple_verify(
            item['challb'].chall, item['domain'], client.key.public_key())
        if not verified:
            raise RuntimeError(
                "Couldn't self-verify that validation "
                "is in place for %s" % item['domain'])

    # then answer all challenges
    logger.info("Answer challenges")
    for item in all_challenges:
        # tell acme server our validations are in place
        client.answer_challenge(item['challb'], item['response'])

    return authorizations


def get_crt(client, csr, authorizations):
    """Get the certificate
    """
    logger.info("Poll and request certificate issuance")
    try:
        wrapped_csr = acme.jose.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM, csr))
        certr, _ = client.poll_and_request_issuance(
            wrapped_csr,
            authorizations,
            # https://github.com/letsencrypt/letsencrypt/issues/1719
            max_attempts=(10 * len(authorizations)))
    except acme.errors.PollError as error:
        if error.timeout:
            raise RuntimeError("Timed out")

        invalid = [authzr for authzr in error.updated.values()
                   if authzr.body.status == acme.messages.STATUS_INVALID]
        if invalid:
            raise RuntimeError(
                "Some authorizations are invalid: %s" % (
                    ', '.join(authzr.uri for authzr in invalid)))

        raise

    pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                          certr.body).strip()
    chain = client.fetch_chain(certr)
    chain_pems = [
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, c).strip()
        for c in chain
    ]

    return pem, chain_pems


def asn1_generalizedtime_to_dt(timestamp):
    """Convert ASN.1 GENERALIZEDTIME to datetime.

    Useful for deserialization of `OpenSSL.crypto.X509.get_notAfter` and
    `OpenSSL.crypto.X509.get_notAfter` outputs.
    """
    dt = datetime.datetime.strptime(timestamp[:12], '%Y%m%d%H%M%S')
    if timestamp.endswith('Z'):
        tzinfo = pytz.utc
    else:
        sign = -1 if timestamp[-5] == '-' else 1
        tzinfo = pytz.FixedOffset(
            sign * (int(timestamp[-4:-2]) * 60 + int(timestamp[-2:])))
    return tzinfo.localize(dt)


def expiration_delay(cert):
    """Returns how long we have until expiration
    """
    now = pytz.utc.localize(datetime.datetime.utcnow())
    expiry = asn1_generalizedtime_to_dt(cert.get_notAfter().decode())
    return expiry - now


def revoke_crt(client, crt):
    """Revokes the given certificate
    """
    # TODO get a thumbprint or something?
    logger.info("Revoking certificate")
    wrapped_crt = acme.jose.ComparableX509(
        OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, crt))
    client.revoke(wrapped_crt)


# EOF

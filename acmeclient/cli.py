#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Basic acme client

Usage:
    acmeclient getcert [-v | -vv | -q] -c <config> [options]
    acmeclient getcert_if_needed [-v | -vv | -q] -c <config> [options]
    acmeclient revoke [-v | -vv | -q] --cert=<cert_file> -c <config> [options]

Options:
    -h --help                       Show this screen.
    --version                       Show version.
    -v --verbose                    Verbose mode.
    -q --quiet                      Quiet mode.
    -c <config> --config=<config>   Path to config file.
    --cert=<cert_file>              Path to cert file (when revoking).
    --print-cert                    Print cert to standard output.
    --print-chain                   Print chain to standard output.
"""

import os
import sys
import datetime
import logging

import yaml
import docopt
import acme

import utils
import challengers

__VERSION__ = ""
logger = logging.getLogger(__name__)


def make_filename(tmpl, config, now=None):
    """Makes filename from template and config
    """
    if tmpl is None:
        return None

    if now is None:
        now = datetime.datetime.utcnow()

    data = {
        'date': now.strftime('%Y%m%d-%H%M%S'),
    }
    data.update(config)

    filename = tmpl.format(**data)
    outdir = config.get('output_dir', '~')
    if outdir:
        path = os.path.expanduser(outdir.format(**data))
        if not os.path.exists(path):
            # create dir
            os.makedirs(path)

        if os.path.isdir(path):
            filename = os.path.join(path, filename)
        else:
            # given path exists but is not a dir, don't use it
            logger.warning("Not using provided output_dir %s" % path)

    return filename


def load_config(filename):
    """Loads config from yaml file
    """
    return yaml.load(open(filename, 'r').read())


def get_client(config):
    """Get acme client file given in config

    If config's client file is empty,
    create a client and save it's data to file
    """
    filename = make_filename(config['client_file'], config)
    try:
        client_config = yaml.load(open(filename, 'r').read())
    except:
        client_config = {}

    raw_key = client_config.get('key')
    isnew = False
    if not raw_key:
        isnew = True
        # create a new key
        key = utils.generate_client_key(config.get('client_key_size', 4096))
        # save it
        client_config['key'] = key.json_dumps()
        open(filename, 'w').write(
            yaml.dump(client_config)
        )
    else:
        # load the key
        key = acme.jose.JWK.json_loads(raw_key)

    client = utils.get_acme_client(
        key,
        server=config.get('server', utils.ACME_SERVER_STAGING),
        user_agent=config.get('user_agent', 'acme client'))

    if isnew:
        # register!
        utils.register_client(client, email=config.get('email'))

    return client


def get_private_key(config):
    """Get private key according to config
    """
    private_key_filename = make_filename(config['private_key_file'], config)
    if os.path.isfile(private_key_filename):
        return open(private_key_filename, 'r').read()

    private_key = utils.generate_private_key(config.get('key_size', 4096))
    # save it
    open(private_key_filename, 'w').write(private_key)
    return private_key


def get_csr(config):
    """Get csr according to config

    If a csr file exists, get csr from file
    Otherwise, generate csr, save it to file and return it
    """
    csr_filename = make_filename(config['csr_file'], config)
    if os.path.isfile(csr_filename):
        # return csr
        return open(csr_filename, 'r').read()

    private_key = get_private_key(config)
    pem, der = utils.generate_csr(private_key, *config.get('domains', []))
    # save it
    open(csr_filename, 'w').write(pem)
    return pem


def get_challenger(config):
    """Get challenger for given config
    """
    ChallengerClass = challengers.import_challenger(config['challenger_class'])
    return ChallengerClass(config)


def get_cert(client, config):
    """Get certificate for the given config
    """
    csr = get_csr(config)
    challenger = get_challenger(config)
    if not isinstance(challenger, utils.Challenger):
        raise ValueError("We expect an instance of Challenger")

    try:
        # validate all domains
        authorizations = utils.answer_challenges(client,
                                                 challenger,
                                                 *config.get('domains', []))
        # get certificate
        crt, chain = utils.get_crt(client, csr, authorizations)
    finally:
        # cleanup challenges
        challenger.cleanup()

    now = datetime.datetime.utcnow()
    crt_filename = make_filename(config.get('crt_file'), config, now)
    if crt_filename:
        # save the crt
        open(crt_filename, 'w').write(crt)

    chain_filename = make_filename(config.get('chain_file'), config, now)
    if chain_filename:
        open(chain_filename, 'w').write('\n'.join(chain))

    chained_crt_filename = make_filename(config.get('chained_crt_file'),
                                         config, now)
    if chained_crt_filename:
        pems = [crt] + chain
        open(chained_crt_filename, 'w').write('\n'.join(pems))

    return crt, chain


def get_cert_if_needed(client, config):
    """Get certificate for the given config only if needed
    """
    # get last crt file

    # if it's there, check expiration, check domains, etc to see if we need to
    # issue a new one

    # if we need a new one, issue it!


def revoke_cert(client, config):
    """Revoke certificate
    """
    # load cert from file
    crt = open(config['--cert'], 'r').read()
    client.revoke(crt)


def main(argv):
    """Main function
    """
    options = docopt.docopt(__doc__, version=__VERSION__)

    # verbosity
    if options['--verbose'] > 1:
        logging.basicConfig(level=logging.DEBUG)
    elif options['--verbose'] > 0:
        logging.basicConfig(level=logging.INFO)
    elif not options['--verbose'] and options['--quiet']:
        # level for quiet is ERROR
        logging.basicConfig(level=logging.ERROR)
    else:
        # default is level WARNING
        logging.basicConfig(level=logging.WARNING)

    # verbosity of external libraries
    if options['--verbose'] > 3:
        logging.getLogger("requests").setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
        logging.getLogger("acme").setLevel(logging.DEBUG)
    elif options['--verbose'] > 2:
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
        logging.getLogger("acme").setLevel(logging.INFO)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("acme").setLevel(logging.WARNING)

    # config
    config = load_config(options['--config'])

    # get to business...
    client = get_client(config)
    if options['getcert']:
        cert, chain = get_cert(client, config)
        if options['--print-cert']:
            print cert

        if options['--print-chain']:
            print "\n".join(chain)

    elif options['getcert_if_needed']:
        get_cert_if_needed(client, config)
    elif options['revoke']:
        revoke_cert(client, config)
    else:
        raise ValueError("Command not recognized")


if __name__ == '__main__':
    main(sys.argv[1:])


# EOF

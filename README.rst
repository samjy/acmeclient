**************************
Another simple ACME client
**************************

This is my attemp to make a simple, flexible, easily configurable ACME client.

It aims at signing web certificates using letsencrypt
(https://letsencrypt.org)

Project status
==============

There are lots of things missing. Here are the main ones:

- There are no tests
- http-01 challenges are not implemented
- The ``getcert_if_needed`` command is not implemented
- setup.py is missing
- A proper virtualenv/bin/acmeclient wrapper script is missing

Why?
====

A website can be deployed on several servers. The available clients weren't
able to easily verificate the challenges, as they act on a single server.

The goal was then to make it easy to get the certificates from one server, and
to then install it on all servers.

Caracteristics
==============

- focus only on getting the certificates (installation is another business!)
- no root permissions needed to get the certificates
- configuration through yaml files (1 file per certificate)
- minimal support for http-01 and dns-01 challenges
- allows to answer http-01 challenges on multiple servers
- allows to answer dns-01 challenges using the OVH API
- easy to extend to answer to challenges in different ways

References
==========

The acme spec:
https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

The official ``acme`` python package is used underneath for doing most of the
hard work (see https://github.com/letsencrypt/letsencrypt/tree/master/acme).

I also had a look at how things are done in the following projects:

- https://github.com/lukas2511/letsencrypt.sh
- https://github.com/kuba/simp_le
- https://github.com/diafygi/acme-tiny

Installation
============

- TODO: write setup.py
- TODO: explain how to setup in a virtualenv

Right now::

  git clone https://github.com/samjy/acmeclient.git
  pip install -r requirements.txt

Testing
=======

There are not tests yet (boooooh!).

- TODO: write the tests
- TODO: here: how to run tests?

Usage
=====

Basic use
---------

#. Create a configuration file (see below) (e.g. ``test.yaml``)
#. Run ``python acmeclient/cli.py getcert -c test.yaml`` to get certificates
#. Install your private key and certificate on your server (ssh, rsync,
   preferably something safe...)

Renew
-----

.. warning::

  Not yet implemented

One of the basic ideas of letsencrypt is that certificates have a short life, so
that we're forced to automate things.

There we go with a cron entry::

  # every 1st of the month at midnight
  0 0 1 * * path/to/python path/to/acmeclient/cli.py getcert_if_needed -c test.yaml && path/to/deploy_script.sh

Revoke certificate
------------------

.. warning::

  Not sure this works

To revoke a certificate, run
``python acmeclient/cli.py revoke --cert=path/to/cert.crt -c test.yaml``

Configuration
=============

Example configuration file
--------------------------

::

  ---
  name: testing

  # --- ACME provider ---
  #server: 'https://acme-v01.api.letsencrypt.org/directory'
  server: 'https://acme-staging.api.letsencrypt.org/directory'

  # --- working directory ---
  output_dir: 'data/{name}'

  # --- account configuration ---
  client_file: '{name}.client.yaml'
  client_key_size: 4096
  email: me@example.com

  # --- certificate configuration ---
  # private key
  key_size: 4096
  private_key_file: '{name}.pkey.pem'
  # domains for the certificate (SANs)
  domains:
    - acmetest1.example.com
    - acmetest2.example.com
    - acmetest3.example.com

  # --- output config ---
  csr_file: '{name}.csr.pem'
  crt_file: '{name}.{date}.crt.pem'
  crt_symlink: '{name}.crt.pem'
  chain_file: '{name}.{date}.chain.pem'
  chain_symlink: '{name}.chain.pem'
  chained_crt_file: '{name}.{date}.chained_crt.pem'
  chained_crt_symlink: '{name}.chained_crt.pem'

  # --- challenger ---
  challenger_class: 'acmeclient.ovh_challenger.OVHDns01Challenger'

  # --- challenger specifics ---
  OVH_APP_KEY: '<ovh app key>'
  OVH_SECRET_KEY: '<ovh secret key>'
  OVH_CONSUMER_KEY: '<ovh consumer key>'

Configuration fields
--------------------

:name: A name for the certificate

:server: URI for the ACME provider

:output_dir: (optional) Path to the output directory. Will contain client_file
             and all keys and certificates files.
             If not given, ``$HOME`` is used

:client_file: A yaml file which will be used to save the client key, and other
              client config

:client_key_size: Size of client key

:email: Email associated to the account

:key_size: Size of certificate key. If the key exists, it doesn't change
           anything

:private_key_file: Private key. If file doesn't exist, a new private key is
                   generated.

:domains: List of domains to be included in the certificate

:csr_file: Certificate signing request. If file doesn't exist, a new CSR is
           generated.

:crt_file: Certificate file. Certificate will be written at this path.

:crt_symlink: Symlink to last certificate file.

:chain_file: Chain file. Where to write the certificate chain.

:chain_symlink: Symlink to last chain file.

:chained_crt_file: Where to write certificate plus chain.

:chained_crt_symlink: Symlink to last chained certificate file.

:challenger_class: The path to a python object able to answer an ACME challenge.

Setup to answer dns-01 challenges with OVH
==========================================

See https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#dns
for the spec.

#. Set challenger class in configuration::

    ---
    challenger_class: 'acmeclient.ovh_challenger.OVHDns01Challenger'

#. Get an application and secret key from OVH: https://eu.api.ovh.com/createApp/
#. Install these in the configuration::

    ---
    challenger_class: 'acmeclient.ovh_challenger.OVHDns01Challenger'
    OVH_APP_KEY: '<the application key>'
    OVH_SECRET_KEY: '<the secret key>'
    OVH_CONSUMER_KEY: ''

#. The consumer key was left empty, but needs to be retrieved once the required
   permissions are given. To give the permissions and retrieve the permissions,
   run the ``ovh_challenger.py`` with the (incomplete) conf::

    python acmeclient/ovh_challenger.py myconf.yaml

   This will give you a link to give permissions
   to the ``/domain`` of the OVH API, and you'll be able to retrieve the
   consumer key once the permissions are given.

#. Install the consumer key in the configuration::

    ---
    challenger_class: 'acmeclient.ovh_challenger.OVHDns01Challenger'
    OVH_APP_KEY: '<the application key>'
    OVH_SECRET_KEY: '<the secret key>'
    OVH_CONSUMER_KEY: '<the consumer key>'

How to write a challenger?
==========================

- one challenger is instanciated for all the domains of the cert
- method ``Challenger.accomplish`` is called for each domain when it's time to
  answer challenges
- before telling the ACME server we've completed the challenges, the method
  ``Challenger.all_accomplished`` is executed.
  (e.g. at this point we wait for DNS propagation in the Dns01Challenger).
- once the ACME challenges have been checked and the certificate issued, or if
  there is an error, ``Challenger.cleanup`` is executed, in order to cleanup the
  validation mess...
  (e.g. delete all records for Dns01Challenger, or remove all files created at
  the ``accomplish`` step for a Http01Challenger)

Changelog
=========

TODO

Contributing
============

TODO

.. EOF

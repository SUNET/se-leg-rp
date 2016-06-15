# -*- coding: utf-8 -*-

from flask import Flask
from requests.exceptions import ConnectionError
from oic.oic import Client
from oic.oic.message import RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
import logging
import sys

from se_leg_rp.db import ProofDB, OidcProofingStateDB
from se_leg_rp.exceptions import init_exception_handlers

__author__ = 'lundberg'

SE_LEG_RP_SETTINGS_ENVVAR = 'SE_LEG_RP_SETTINGS'


def init_oidc_client(app):
    oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    oidc_client.store_registration_info(RegistrationRequest(**app.config['CLIENT_REGISTRATION_INFO']))
    provider = app.config['PROVIDER_CONFIGURATION_INFO']['issuer']
    try:
        oidc_client.provider_config(provider)
    except ConnectionError as e:
        app.logger.critical('No connection to provider {!s}. Can not start without provider configuration.'.format(
            provider))
        raise e
    return oidc_client


def init_logging(app):
    """
    :param app: Flask app
    :type app: flask.app.Flask
    :return: Flask app with log handlers
    :rtype: flask.app.Flask
    """
    app.config.setdefault('LOG_LEVEL', 'INFO')
    root_logger = logging.getLogger()
    root_logger.setLevel(app.config['LOG_LEVEL'])
    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root_logger.addHandler(ch)
    app.logger.info('Logging initiated')
    return app


def se_leg_rp_init_app(name, config):
    """
    Create an instance of an se_leg_rp app.

    First, it will load the configuration from settings.common, settings.dev then any settings
    given in the `config` param.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = Flask(name)

    app.config.from_object('se_leg_rp.settings.common')
    app.config.from_envvar(SE_LEG_RP_SETTINGS_ENVVAR, silent=False)
    app.config.update(config)

    # Initialize helpers
    app = init_exception_handlers(app)
    app = init_logging(app)

    from .views import se_leg_rp_views
    app.register_blueprint(se_leg_rp_views)

    # Initialize the oidc_client after views to be able to set correct redirect_uris
    app.oidc_client = init_oidc_client(app)

    # Initialize db
    app.proofing_statedb = OidcProofingStateDB(app.config['MONGO_URI'])
    app.proofdb = ProofDB(app.config['MONGO_URI'])

    app.logger.info('Started {!s}'.format(name))

    return app


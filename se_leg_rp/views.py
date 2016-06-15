# -*- coding: utf-8 -*-

from flask import request, url_for, make_response
from flask import current_app, Blueprint
from flask_apispec import use_kwargs, marshal_with
from oic.oic.message import AuthorizationResponse, ClaimsRequest, Claims
from operator import itemgetter
import requests
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
from se_leg_rp.utils import get_unique_hash
from se_leg_rp.exceptions import ApiException
from eduid_userdb.proofing import OidcProofingState
from se_leg_rp import schemas
from se_leg_rp import mock_auth
from se_leg_rp.db import Proof, DocumentDoesNotExist

__author__ = 'lundberg'

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

se_leg_rp_views = Blueprint('se_leg_rp', __name__, url_prefix='')


@se_leg_rp_views.route('/authorization-response')
def authorization_response():
    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {!s}'.format(query_string))
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {!s}'.format(authn_resp))

    if authn_resp.get('error'):
        current_app.logger.error('AuthorizationError {!s} - {!s} ({!s})'.format(request.host, authn_resp['error'],
                                                                                authn_resp.get('error_message'),
                                                                                authn_resp.get('error_uri')))
        return make_response('OK', 200)

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        msg = 'The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state)
        current_app.logger.error(msg)
        raise ApiException(payload={'error': msg})
    current_app.logger.debug('Proofing state {!s} for user {!s} found'.format(proofing_state.state,
                                                                              proofing_state.eppn))
    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': url_for('se_leg_rp.authorization_response', _external=True)
    }
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    token_resp = current_app.oidc_client.do_access_token_request(scope='openid', state=authn_resp['state'],
                                                                 request_args=args,
                                                                 authn_method='client_secret_basic')
    current_app.logger.debug('token response received: {!s}'.format(token_resp))
    id_token = token_resp['id_token']
    if id_token['nonce'] != proofing_state.nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user {!s}.'.format(proofing_state.eppn))
        raise ApiException(payload={'error': 'The \'nonce\' parameter does not match match.'})

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    userinfo = current_app.oidc_client.do_user_info_request(method=current_app.config['USERINFO_ENDPOINT_METHOD'],
                                                            state=authn_resp['state'])
    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error('The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(
            proofing_state.eppn))
        raise ApiException(payload={'The \'sub\' of userinfo does not match \'sub\' of ID Token'})

    # Save proof
    proof_data = {
        'eduPersonPrincipalName': proofing_state.eppn,
        'authn_resp': authn_resp.to_dict(),
        'token_resp': token_resp.to_dict(),
        'userinfo': userinfo.to_dict()
    }

    current_app.proofdb.save(Proof(data=proof_data))

    # Remove users proofing state
    current_app.proofing_statedb.remove_state(proofing_state)
    return make_response('OK', 200)


@se_leg_rp_views.route('/get-state', methods=['POST'])
@use_kwargs(schemas.EppnRequestSchema)
@marshal_with(schemas.NonceResponseSchema)
def get_state(**kwargs):
    eppn = mock_auth.authenticate(kwargs)
    current_app.logger.debug('Getting state for user with eppn {!s}.'.format(eppn))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found, initializing new proofing flow.'.format(eppn))
        state = get_unique_hash()
        nonce = get_unique_hash()
        proofing_state = OidcProofingState({'eduPersonPrincipalName': eppn, 'state': state, 'nonce': nonce})
        # Initiate proofing
        args = {
            'client_id': current_app.oidc_client.client_id,
            'response_type': 'code id_token token',
            'response_mode': 'query',
            'scope': ['openid'],
            'redirect_uri': url_for('se_leg_rp.authorization_response', _external=True),
            'state': state,
            'nonce': nonce,
            'claims': ClaimsRequest(userinfo=Claims(identity=None)).to_json()
        }
        current_app.logger.debug('AuthenticationRequest args:')
        current_app.logger.debug(args)
        try:
            response = requests.post(current_app.oidc_client.authorization_endpoint, data=args)
        except requests.exceptions.ConnectionError as e:
            msg = 'No connection to authorization endpoint: {!s}'.format(e)
            current_app.logger.error(msg)
            raise ApiException(payload={'error': msg})
        # If authentication request went well save user state
        if response.status_code == 200:
            current_app.logger.debug('Authentication request delivered to provider {!s}'.format(
                current_app.config['PROVIDER_CONFIGURATION_INFO']['issuer']))
            current_app.proofing_statedb.save(proofing_state)
            current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, eppn))
        else:
            payload = {'error': response.reason, 'message': response.content}
            raise ApiException(status_code=response.status_code, payload=payload)
    # Return nonce and nonce as qr code
    current_app.logger.debug('Returning nonce for user {!s}'.format(eppn))
    buf = BytesIO()
    qrcode.make(proofing_state.nonce).save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    ret = {
        'nonce': proofing_state.nonce,
        'qr_img': '<img src="data:image/png;base64, {!s}"/>'.format(qr_b64),
    }
    return ret


@se_leg_rp_views.route('/proofs', methods=['POST'])
@use_kwargs(schemas.EppnRequestSchema)
@marshal_with(schemas.ProofResponseSchema)
def proofs(**kwargs):
    eppn = mock_auth.authenticate(kwargs)
    current_app.logger.debug('Getting proofs for user with eppn {!s}.'.format(eppn))
    try:
        proof_data = current_app.proofdb.get_proofs_by_eppn(eppn)
    except DocumentDoesNotExist:
        return {'proofs': []}
    data = []
    for proof in proof_data:
        tmp = proof.to_dict()
        del tmp['_id']
        data.append(tmp)
    data = sorted(data, key=itemgetter('modified_ts'), reverse=True)
    return {'proofs': data}


# -*- coding: utf-8 -*-
import json

from flask import request, make_response
from flask import current_app, Blueprint
from flask_apispec import use_kwargs, marshal_with
from oic.oic.message import AuthorizationResponse, ClaimsRequest, Claims

import qrcode
import qrcode.image.svg
from io import BytesIO
import base64

from se_leg_rp.utils import get_unique_hash, check_auth_header, do_initial_token_request, do_authentication_request
from se_leg_rp.utils import do_initial_userinfo_request, get_user_proofing_state
from se_leg_rp.exceptions import ApiException
from eduid_userdb.proofing import OidcProofingState
from se_leg_rp import schemas
from se_leg_rp import mock_auth
from se_leg_rp.db import Proof

__author__ = 'lundberg'

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

nstic_views = Blueprint('vetting', __name__, url_prefix='')

# flask-registry hook
blueprints = [nstic_views]


@nstic_views.route('/authorization-response')
def authorization_response():
    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {}'.format(query_string))
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {}'.format(authn_resp))

    if authn_resp.get('error'):
        current_app.logger.error('AuthorizationError {} - {} ({})'.format(request.host, authn_resp['error'],
                                                                          authn_resp.get('error_message'),
                                                                          authn_resp.get('error_uri')))
        return make_response('OK', 200)

    # get user proofing state from db
    proofing_state = get_user_proofing_state(authn_resp['state'])

    # Make sure the Bearer Token matches the one generated at authn request time
    if check_auth_header(proofing_state.token):
        # Use the authn code to request token information
        token_resp = do_initial_token_request(authn_resp['code'], authn_resp['state'], proofing_state.nonce)
        # After receiving a token response the client has stored the grant so we only need to supply
        # state to load the grant from the client.grant cache.
        userinfo = do_initial_userinfo_request(authn_resp['state'], token_resp['id_token']['sub'])

        # Save proof
        proof_data = {
            'eduPersonPrincipalName': proofing_state.eppn,
            'authn_resp': authn_resp.to_dict(),
            'token_resp': token_resp.to_dict(),
            'userinfo': userinfo.to_dict()
        }

        current_app.proofdb.save(Proof(data=proof_data))

    return make_response('OK', 200)


@nstic_views.route('/get-state', methods=['POST'])
@use_kwargs(schemas.EppnRequestSchema)
@marshal_with(schemas.NonceResponseSchema)
def get_state(**kwargs):
    eppn = mock_auth.authenticate(kwargs)
    current_app.logger.debug('Getting state for user with eppn {}.'.format(eppn))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found, initializing new proofing flow.'.format(eppn))
        state = get_unique_hash()
        nonce = get_unique_hash()
        token = get_unique_hash()
        proofing_state = OidcProofingState({'eduPersonPrincipalName': eppn, 'state': state, 'nonce': nonce,
                                            'token': token})
        claims_request = ClaimsRequest(userinfo=Claims(vetting_result=None))
        # Initiate proofing
        response = do_authentication_request(state, nonce, token, claims_request)
        if response.status_code != 200:
            payload = {'error': response.reason, 'message': response.content}
            raise ApiException(status_code=response.status_code, payload=payload)
        # If authentication request went well save user state
        current_app.proofing_statedb.save(proofing_state)
        current_app.logger.debug('Proofing state {} for user {} saved'.format(proofing_state.state, eppn))

    # Return nonce and nonce as qr code
    current_app.logger.debug('Returning nonce+token for user {}'.format(eppn))
    buf = BytesIO()
    qr_code = '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token})
    qrcode.make(qr_code).save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    ret = {
        'qr_code': qr_code,
        'qr_img': '<img src="data:image/png;base64, {}"/>'.format(qr_b64),
    }
    return ret

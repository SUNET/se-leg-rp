# -*- coding: utf-8 -*-

from flask import make_response
from flask import current_app, Blueprint
from flask_apispec import use_kwargs, marshal_with
from oic.exception import PyoidcError
from operator import itemgetter

import uuid
from se_leg_rp.exceptions import ApiException
from se_leg_rp import schemas
from se_leg_rp import mock_auth
from se_leg_rp.db import DocumentDoesNotExist

__author__ = 'lundberg'


rp_views = Blueprint('rp', __name__, url_prefix='')


@rp_views.route('/refresh-access-token', methods=['POST'])
@use_kwargs(schemas.EppnRequestSchema)
def refresh_access_token(**kwargs):

    eppn = mock_auth.authenticate(kwargs)
    current_app.logger.debug('Getting userinfo for user with eppn {!s}.'.format(eppn))
    try:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(eppn, raise_on_missing=False)
        proof_data = current_app.proofdb.get_proofs_by_eppn(eppn)
    except DocumentDoesNotExist:
        return {'error': 'No data for user'}

    args = {
        'refresh_token': proof_data[0].token_resp['refresh_token']
    }
    response = current_app.oidc_client.do_access_token_refresh(method=current_app.config['REFRESH_TOKEN_ENDPOINT_METHOD'],
                                                               state=proofing_state.state,
                                                               token=None,
                                                               request_args=args,
                                                               authn_method='client_secret_basic')
    proof = proof_data[0]
    current_app.logger.debug('Refresh access token response: {}'.format(response))
    proof.token_resp.update({
            'token_type': response['token_type'],
            'access_token': response['access_token'],
         }
    )
    # A new refresh token is only supplied if the the OP has a set lifetime for refresh tokens
    if 'refresh_token' in response:
        proof.token_resp['refresh_token'] = response['refresh_token']

    current_app.proofdb.save(proof)
    return make_response('OK', 200)


@rp_views.route('/userinfo', methods=['POST'])
@use_kwargs(schemas.EppnRequestSchema)
@marshal_with(schemas.UserinfoResponseSchema)
def get_userinfo(**kwargs):
    eppn = mock_auth.authenticate(kwargs)
    current_app.logger.debug('Getting userinfo for user with eppn {!s}.'.format(eppn))
    try:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(eppn, raise_on_missing=False)
        proof_data = current_app.proofdb.get_proofs_by_eppn(eppn)
    except DocumentDoesNotExist:
        return {'userinfo': {}}

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    try:
        userinfo = current_app.oidc_client.do_user_info_request(method=current_app.config['USERINFO_ENDPOINT_METHOD'],
                                                                state=proofing_state.state,
                                                                access_token=proof_data[0].token_resp['access_token'],
                                                                claims={'data'})
    except PyoidcError as e:
        current_app.logger.error(e)
        # Probably access token expired
        refresh_access_token(**kwargs)
        return {'userinfo': {'message': 'Refreshed access token, try again.'}}

    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    id_token = proof_data[0].token_resp['id_token']
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error('The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(
            proofing_state.eppn))
        raise ApiException(payload={'The \'sub\' of userinfo does not match \'sub\' of ID Token'})

    proof = proof_data[0]
    current_app.logger.debug(userinfo)
    proof.userinfo.update(userinfo)
    current_app.proofdb.save(proof)

    return {'userinfo': userinfo.to_dict()}


@rp_views.route('/proofs', methods=['POST'])
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

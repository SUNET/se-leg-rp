# -*- coding: utf-8 -*-

__author__ = 'lundberg'

"""
For more built in configuration options see,
http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values
"""

# -*- coding: utf-8 -*-

#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

# ==============#
# Flask config #
# ==============#

# enable/disable debug mode
DEBUG = False

# enable/disable testing mode
TESTING = False

# explicitly enable or disable the propagation of exceptions.
# If not set or explicitly set to None this is implicitly true if either
# TESTING or DEBUG is true.
PROPAGATE_EXCEPTIONS = None

# By default if the application is in debug mode the request context is not
# popped on exceptions to enable debuggers to introspect the data. This can be
# disabled by this key. You can also use this setting to force-enable it for non
# debug execution which might be useful to debug production applications (but
# also very risky).
PRESERVE_CONTEXT_ON_EXCEPTION = False

# the secret key
SECRET_KEY = ''

# the name of the session cookie
SESSION_COOKIE_NAME = 'sessid'

# the domain for the session cookie. If this is not set, the cookie will
# be valid for all subdomains of SERVER_NAME.
SESSION_COOKIE_DOMAIN = ''

# the path for the session cookie. If this is not set the cookie will be valid
# for all of APPLICATION_ROOT or if that is not set for '/'.
SESSION_COOKIE_PATH = '/'

# controls if the cookie should be set with the httponly flag. Defaults to True
SESSION_COOKIE_HTTPONLY = False

# controls if the cookie should be set with the secure flag. Defaults to False
SESSION_COOKIE_SECURE = False

# the lifetime of a permanent session as datetime.timedelta object.
# Starting with Flask 0.8 this can also be an integer representing seconds.
PERMANENT_SESSION_LIFETIME = 3600

# enable/disable x-sendfile
# USE_X_SENDFILE = False

# the name of the logger
LOGGER_NAME = 'se_leg_rp'

# the name and port number of the server. Required for subdomain support
# (e.g.: 'myapp.dev:5000') Note that localhost does not support subdomains
# so setting this to “localhost” does not help. Setting a SERVER_NAME also
# by default enables URL generation without a request context but with an
# application context.
# SERVER_NAME = ''

# If the application does not occupy a whole domain or subdomain this can be
# set to the path where the application is configured to live. This is for
# session cookie as path value. If domains are used, this should be None.
# APPLICATION_ROOT = ''

# If set to a value in bytes, Flask will reject incoming requests with a
# content length greater than this by returning a 413 status code.
# MAX_CONTENT_LENGTH

# Default cache control max age to use with send_static_file() (the default
# static file handler) and send_file(), in seconds. Override this value on a
# per-file basis using the get_send_file_max_age() hook on Flask or Blueprint,
# respectively. Defaults to 43200 (12 hours).
SEND_FILE_MAX_AGE_DEFAULT = 43200

# If this is set to True Flask will not execute the error handlers of HTTP
# exceptions but instead treat the exception like any other and bubble it through
# the exception stack. This is helpful for hairy debugging situations where you
# have to find out where an HTTP exception is coming from.
TRAP_HTTP_EXCEPTIONS = False

# Werkzeug’s internal data structures that deal with request specific data
# will raise special key errors that are also bad request exceptions. Likewise
# many operations can implicitly fail with a BadRequest exception for
# consistency. Since it’s nice for debugging to know why exactly it failed this
# flag can be used to debug those situations. If this config is set to True you
# will get a regular traceback instead.
TRAP_BAD_REQUEST_ERRORS = False

# The URL scheme that should be used for URL generation if no URL scheme is
# available. This defaults to http.
PREFERRED_URL_SCHEME = 'http'

# By default Flask serialize object to ascii-encoded JSON. If this is set to
# False Flask will not encode to ASCII and output strings as-is and return
# unicode strings. jsonfiy will automatically encode it in utf-8 then for
# transport for instance.
JSON_AS_ASCII = False

# By default Flask will serialize JSON objects in a way that the keys are
# ordered. This is done in order to ensure that independent of the hash seed of
# the dictionary the return value will be consistent to not trash external HTTP
# caches. You can override the default behavior by changing this variable. This
# is not recommended but might give you a performance improvement on the cost of
# cachability.
# JSON_SORT_KEYS = True

# If this is set to True (the default) jsonify responses will be pretty printed
# if they are not requested by an XMLHttpRequest object (controlled by the
# X-Requested-With header)
# JSONIFY_PRETTYPRINT_REGULAR


# ================#
#  mongodb config #
# ================#

MONGO_URI = 'mongodb://'

# ================#
# OIDC            #
# ================#
CLIENT_REGISTRATION_INFO = {
    'client_id': 'can_not_be_empty_string',
    'client_secret': ''
}

PROVIDER_CONFIGURATION_INFO = {
    'issuer': 'can_not_be_empty_string',
}

USERINFO_ENDPOINT_METHOD = 'POST'
REFRESH_TOKEN_ENDPOINT_METHOD = 'POST'

# ================#
# se-leg-rp       #
# ================#

# In which plugin package to find views
PACKAGES = []

"""
Flask app for testing the OpenID Connect extension.
"""

from distutils.command.config import config
import json
from venv import create

from flask import Flask, g
from flask_oidc import OpenIDConnect
from pkg_resources import resource_filename, resource_stream
import codecs
from six.moves.urllib.parse import urlsplit, parse_qs, urlencode

oidc = None

def callback_url_for(response):
    """
    Take a redirect to the IdP and turn it into a redirect from the IdP.
    :return: The URL that the IdP would have redirected the user to.
    """
    location = urlsplit(response.headers['Location'])
    query = parse_qs(location.query)
    state = query['state'][0]
    callback_url = '/oidc_callback?'\
                   + urlencode({'state': state, 'code': 'mock_auth_code'})
    return callback_url

def loggedIn():
    return "Logged In", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def loggedOut():

    return "Logged Out", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def index():
    return "too many secrets", 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def get_at():
    return oidc.get_access_token(), 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def get_rt():
    return oidc.get_refresh_token(), 200, {
        'Content-Type': 'text/plain; charset=utf-8'
    }

def raw_api():
    return {'token': g.oidc_token_info}

def api():
    return json.dumps(raw_api())

# @app.route("/logout", method=["GET"])
# def logout():
#     return oidc.logout()


def create_app(config, oidc_overrides=None):
    global oidc

    app = Flask(__name__)
    app.config.update(config)
    if oidc_overrides is None:
        oidc_overrides = {}
    oidc = OpenIDConnect(app, **oidc_overrides)
    app.route('/')(oidc.check(index))
    app.route('/at')(oidc.check(get_at))
    app.route('/rt')(oidc.check(get_rt))
    app.route('/hello')(oidc.require_login(loggedIn))

    # Check standalone usage
    rendered = oidc.accept_token(True, ['openid'])(api)
    app.route('/api', methods=['GET', 'POST'])(rendered)


    # logout usage
    def logout():
        result = oidc.logout()
        return "Logged Out", 200, {
            'Content-Type': 'text/plain; charset=utf-8'
        }
    app.route("/logout")(oidc.require_login(logout))

    # Check combination with an external API renderer like Flask-RESTful
    unrendered = oidc.accept_token(True, ['openid'], render_errors=False)(raw_api)
    def externally_rendered_api(*args, **kwds):
        inner_response = unrendered(*args, **kwds)
        if isinstance(inner_response, tuple):
            raw_response, response_code, headers = inner_response
            rendered_response = json.dumps(raw_response), response_code, headers
        else:
            rendered_response = json.dumps(inner_response)
        return rendered_response
    app.route('/external_api', methods=['GET', 'POST'])(externally_rendered_api)




    return app


app_configs = {
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    # 'OIDC_OPENID_REALM': 'http://localhost:5000/oidc_callback',
    "OIDC_COOKIE_SECURE": False,
    "OIDC_CALLBACK_ROUTE": "/oidc_callback",
    "OIDC_SCOPES": ["openid", "email", "profile"]
    
}

if __name__ == "__main__":
    app = create_app(app_configs)

    app.run()
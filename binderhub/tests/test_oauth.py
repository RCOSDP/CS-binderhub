"""Test for OAuth modules"""

import re
from urllib.parse import urlparse

import pytest

from .utils import async_requests


@pytest.fixture
def use_session():
    # setup
    async_requests.set_session()
    yield "run the test function"
    # teardown
    async_requests.delete_session()


async def test_oauth_flow(app, use_session):
    url = f'{app.url}/api/oauth2/authorize?client_id=AAAA&response_type=code'
    r = await async_requests.get(url, allow_redirects=False)
    location_pattern = re.compile(r'http\:\/\/192\.168\.168\.167\:5000\/project\/binderhub\/callback\?code=([^=&]+)')
    assert r.status_code == 302 and location_pattern.match(r.headers['Location']), f"{r.status_code} {url}"

    code = location_pattern.match(r.headers['Location']).group(1)
    url = f'{app.url}/api/oauth2/token'
    payload = {
        'grant_type': 'authorization_code',
        'client_id': 'AAAA',
        'client_secret': 'BBBB',
        'code': code,
        'redirect_uri': 'http://192.168.168.167:5000/project/binderhub/callback',
    }
    r = await async_requests.post(url, data=payload)
    assert r.status_code == 200, f"{r.status_code} {url}"
    assert r.json()['token_type'] == 'Bearer'
    assert r.json()['scope'] == 'identify'
    assert r.json()['expires_in'] == 3600
    assert 'access_token' in r.json()

    url = f'{app.url}/api/services'
    access_token = r.json()['access_token']
    r = await async_requests.get(url, headers={
        'Authorization': 'Bearer {}'.format(access_token),
    })
    assert r.status_code == 200, f"{r.status_code} {url}"
    services = r.json()
    assert len(services) == 1 and services[0]['type'] == 'jupyterhub' \
        and services[0]['url'] is not None

@pytest.mark.parametrize(
    'app,path',
    [
        (True, '/api/services'),
    ],
    indirect=['app']  # send param True to app fixture, so that it loads authentication configuration
)
async def test_api_not_authenticated(app, path, use_session):
    url = f'{app.url}{path}'
    r = await async_requests.get(url, allow_redirects=False)
    assert r.status_code == 403, f"{r.status_code} {url}"

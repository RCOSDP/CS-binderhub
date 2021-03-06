"""Base classes for request handlers"""

import json
from ipaddress import ip_address
from urllib.parse import urlparse

from http.client import responses
from tornado import web
from tornado.log import app_log
from jupyterhub.services.auth import HubOAuthenticated, HubOAuth

from . import __version__ as binder_version
from .utils import ip_in_networks


class BaseHandler(HubOAuthenticated, web.RequestHandler):
    """HubAuthenticated by default allows all successfully identified users (see allow_all property)."""

    def initialize(self):
        super().initialize()
        if self.settings['auth_enabled']:
            self.hub_auth = HubOAuth.instance(config=self.settings['traitlets_config'])

    def prepare(self):
        super().prepare()
        # check request ips early on all handlers
        self.check_request_ip()

    skip_check_request_ip = False

    def check_request_ip(self):
        """Check network block list, if any"""
        ban_networks = self.settings.get("ban_networks")
        if self.skip_check_request_ip or not ban_networks:
            return
        request_ip = self.request.remote_ip
        match = ip_in_networks(
            request_ip,
            ban_networks,
            min_prefix_len=self.settings["ban_networks_min_prefix_len"],
        )
        if match:
            network, message = match
            app_log.warning(
                f"Blocking request from {request_ip} matching banned network {network}: {message}"
            )
            raise web.HTTPError(403, f"Requests from {message} are not allowed")

    def get_current_user(self):
        token_provider = self.settings.get('oauth2_token_provider', None)
        if token_provider is not None:
            user = token_provider.get_user_token(self)
            if user is not None:
                return user
        if not self.settings['auth_enabled']:
            return 'anonymous'
        return super().get_current_user()

    @property
    def template_namespace(self):
        return dict(static_url=self.static_url,
                    banner=self.settings['banner_message'],
                    **self.settings.get('template_variables', {}))

    def set_default_headers(self):
        headers = self.settings.get('headers', {})
        for header, value in headers.items():
            self.set_header(header, value)
        self.set_header("access-control-allow-headers", "cache-control")
        if self._is_allowed_request():
            self.set_header(
                'Access-Control-Allow-Origin', self.request.headers['Origin']
            )

    def _is_allowed_request(self):
        allowed_hosts = self.settings.get('allowed_hosts', [])
        if allowed_hosts is None or len(allowed_hosts) == 0:
            return False
        origin = self.request.headers.get('Origin', None)
        if origin is None:
            return False
        domain = urlparse(origin).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain in allowed_hosts

    def get_spec_from_request(self, prefix):
        """Re-extract spec from request.path.
        Get the original, raw spec, without tornado's unquoting.
        This is needed because tornado converts 'foo%2Fbar/ref' to 'foo/bar/ref'.
        """
        idx = self.request.path.index(prefix)
        spec = self.request.path[idx + len(prefix) + 1:]
        return spec

    def get_provider(self, provider_prefix, spec):
        """Construct a provider object"""
        providers = self.settings['repo_providers']
        if provider_prefix not in providers:
            raise web.HTTPError(404, "No provider found for prefix %s" % provider_prefix)

        return providers[provider_prefix](
            config=self.settings['traitlets_config'], spec=spec)

    def get_badge_base_url(self):
        badge_base_url = self.settings['badge_base_url']
        if callable(badge_base_url):
            badge_base_url = badge_base_url(self)
        return badge_base_url

    def render_template(self, name, **extra_ns):
        """Render an HTML page"""
        ns = {}
        ns.update(self.template_namespace)
        ns.update(extra_ns)
        template = self.settings['jinja2_env'].get_template(name)
        html = template.render(**ns)
        self.write(html)

    def extract_message(self, exc_info):
        """Return error message from exc_info"""
        exception = exc_info[1]
        # get the custom message, if defined
        try:
            return exception.log_message % exception.args
        except Exception:
            return ''

    def write_error(self, status_code, **kwargs):
        exc_info = kwargs.get('exc_info')
        message = ''
        status_message = responses.get(status_code, 'Unknown HTTP Error')
        if exc_info:
            message = self.extract_message(exc_info)

        self.render_template(
            'error.html',
            status_code=status_code,
            status_message=status_message,
            message=message,
        )

    def options(self, *args, **kwargs):
        pass


class Custom404(BaseHandler):
    """Raise a 404 error, rendering the error.html template"""

    def prepare(self):
        raise web.HTTPError(404)


class AboutHandler(BaseHandler):
    """Serve the about page"""
    async def get(self):
        self.render_template(
            "about.html",
            base_url=self.settings['base_url'],
            submit=False,
            binder_version=binder_version,
            message=self.settings['about_message'],
            google_analytics_code=self.settings['google_analytics_code'],
            google_analytics_domain=self.settings['google_analytics_domain'],
            extra_footer_scripts=self.settings['extra_footer_scripts'],
        )


class VersionHandler(BaseHandler):
    """Serve information about versions running"""

    # demote logging of 200 responses to debug-level
    log_success_debug = True
    # allow version-check requests from banned hosts
    # (e.g. mybinder.org federation when blocking cloud datacenters)
    skip_check_request_ip = True

    async def get(self):
        self.set_header("Content-type", "application/json")
        self.write(json.dumps(
            {
                "builder": self.settings['build_image'],
                "binderhub": binder_version,
                }
        ))

"""Base classes for request handlers"""

import json
import urllib.parse

import jwt
from jupyterhub.services.auth import HubOAuth, HubOAuthenticated
from tornado import web
from tornado.log import app_log

from . import __version__ as binder_version
from .ratelimit import RateLimitExceeded
from .utils import ip_in_networks


class BaseHandler(HubOAuthenticated, web.RequestHandler):
    """HubAuthenticated by default allows all successfully identified users (see allow_all property)."""

    def initialize(self):
        super().initialize()
        if self.settings["auth_enabled"]:
            self.hub_auth = HubOAuth.instance(config=self.settings["traitlets_config"])

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
        )
        if match:
            network_spec = match
            message = ban_networks[network_spec]
            app_log.warning(
                f"Blocking request from {request_ip} matching banned network {network_spec}: {message}"
            )
            raise web.HTTPError(403, f"Requests from {message} are not allowed")

    def token_origin(self):
        """Compute the origin used by build tokens

        For build tokens we check the Origin and then the Host header to
        compute the "origin" of a build token.
        """
        origin_or_host = self.request.headers.get("origin", None)
        if origin_or_host is not None:
            # the origin header includes the scheme, which the host header
            # doesn't so we normalize Origin to the format of Host
            origin_or_host = urllib.parse.urlparse(origin_or_host).netloc
        else:
            origin_or_host = self.request.headers.get("host", "")

        return origin_or_host

    def check_build_token(self, build_token, provider_spec):
        """Validate that a build token is valid for the current request

        Sets `_have_build_token` boolean property to:
        - True if a token is present and valid
        - False if not present
        Raises 403 if a token is present but not valid
        """
        if not build_token:
            app_log.debug(f"No build token for {provider_spec}")
            self._have_build_token = False
            return
        try:
            decoded = jwt.decode(
                build_token,
                key=self.settings["build_token_secret"],
                audience=provider_spec,
                algorithms=["HS256"],
            )
        except jwt.PyJWTError as e:
            app_log.error(f"Failure to validate build token for {provider_spec}: {e}")
            raise web.HTTPError(403, "Invalid build token")

        origin = self.token_origin()
        if decoded["origin"] != origin:
            app_log.error(
                f"Build token from mismatched origin != {origin}: {decoded};"
                f" Host={self.request.headers.get('host')}, Origin={self.request.headers.get('origin')}"
            )
            if self.settings["build_token_check_origin"]:
                raise web.HTTPError(403, "Invalid build token")
        app_log.debug(f"Accepting build token for {provider_spec}")
        self._have_build_token = True
        return decoded

    def check_rate_limit(self):
        rate_limiter = self.settings["rate_limiter"]
        if rate_limiter.limit == 0:
            # no limit enabled
            return

        if self.settings["auth_enabled"] and self.current_user:
            # authenticated, no limit
            # TODO: separate authenticated limit
            return

        if self._have_build_token:
            # build token defined, no limit
            # TODO: use different limit for verified builds
            return

        # rate limit is applied per-ip
        request_ip = self.request.remote_ip
        try:
            limit = rate_limiter.increment(request_ip)
        except RateLimitExceeded:
            raise web.HTTPError(
                429,
                f"Rate limit exceeded. Try again in {rate_limiter.period_seconds} seconds.",
            )
        else:
            app_log.debug(f"Rate limit for {request_ip}: {limit}")

        self.set_header("x-ratelimit-remaining", str(limit["remaining"]))
        self.set_header("x-ratelimit-reset", str(limit["reset"]))
        self.set_header("x-ratelimit-limit", str(rate_limiter.limit))

    def get_current_user(self):
        token_provider = self.settings.get("oauth2_token_provider", None)
        if token_provider is not None:
            user = token_provider.get_user_token(self)
            if user is not None:
                return user
        if not self.settings["auth_enabled"]:
            return "anonymous"
        return super().get_current_user()

    @property
    def template_namespace(self):

        ns = dict(
            static_url=self.static_url,
            banner=self.settings["banner_message"],
            auth_enabled=self.settings["auth_enabled"],
        )
        if self.settings["auth_enabled"]:
            ns["xsrf"] = self.xsrf_token.decode("ascii")
            ns["api_token"] = self.hub_auth.get_token(self) or ""

        ns.update(
            self.settings.get("template_variables", {}),
        )
        return ns

    def set_default_headers(self):
        headers = self.settings.get("headers", {})
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
        domain = urllib.parse.urlparse(origin).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain in allowed_hosts

    def get_spec_from_request(self, prefix):
        """Re-extract spec from request.path.
        Get the original, raw spec, without tornado's unquoting.
        This is needed because tornado converts 'foo%2Fbar/ref' to 'foo/bar/ref'.
        """
        idx = self.request.path.index(prefix)
        spec = self.request.path[idx + len(prefix) + 1 :]
        return spec

    def get_provider(self, provider_prefix, spec):
        """Construct a provider object"""
        providers = self.settings["repo_providers"]
        if provider_prefix not in providers:
            raise web.HTTPError(404, f"No provider found for prefix {provider_prefix}")

        return providers[provider_prefix](
            config=self.settings["traitlets_config"], spec=spec
        )

    def get_badge_base_url(self):
        badge_base_url = self.settings["badge_base_url"]
        if callable(badge_base_url):
            badge_base_url = badge_base_url(self)
            # Make sure the url has a trailing slash
            if not badge_base_url.endswith("/"):
                badge_base_url += "/"
        return badge_base_url

    def render_template(self, name, **extra_ns):
        """Render an HTML page"""
        ns = {}
        ns.update(self.template_namespace)
        ns.update(extra_ns)
        template = self.settings["jinja2_env"].get_template(name)
        html = template.render(**ns)
        self.write(html)

    def extract_message(self, exc_info):
        """Return error message from exc_info"""
        exception = exc_info[1]
        # get the custom message, if defined
        try:
            return exception.log_message % exception.args
        except Exception:
            return ""

    def options(self, *args, **kwargs):
        pass


class VersionHandler(BaseHandler):
    """Serve information about versions running"""

    # demote logging of 200 responses to debug-level
    log_success_debug = True
    # allow version-check requests from banned hosts
    # (e.g. mybinder.org federation when blocking cloud datacenters)
    skip_check_request_ip = True

    def set_default_headers(self):
        if "Access-Control-Allow-Origin" not in self.settings.get("headers", {}):
            # allow CORS requests to this endpoint by default
            self.set_header("Access-Control-Allow-Origin", "*")

        super().set_default_headers()

    async def get(self):
        self.set_header("Content-type", "application/json")
        r = {
            "builder_info": self.settings["example_builder"].builder_info,
            "binderhub": binder_version,
        }
        # Backwards compatibility
        if "build_image" in r["builder_info"]:
            r["builder"] = r["builder_info"]["build_image"]
        self.write(json.dumps(r))

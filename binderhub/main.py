"""
Main handler classes for requests
"""

import time

import jwt
from tornado.httputil import url_concat
from tornado.web import authenticated

from . import __version__ as binder_version
from .base import BaseHandler


class UIHandler(BaseHandler):
    """
    Responds to most UI Page Requests
    """

    def initialize(self):
        self.opengraph_title = self.settings["default_opengraph_title"]
        self.page_config = {}
        return super().initialize()

    @authenticated
    async def get(self):
        repoproviders_display_config = [
            repo_provider_class.display_config
            for repo_provider_class in self.settings["repo_providers"].values()
        ]
        running_environment_count = None
        launcher = self.settings.get("launcher")
        if launcher is not None:
            try:
                user = self.get_current_user()
                username = user.get("name") if isinstance(user, dict) else user
                if username:
                    running_environment_count = await launcher.get_named_server_count(
                        username
                    )
            except Exception:
                self.log.debug(
                    "Unable to determine current environment count", exc_info=True
                )
        self.page_config |= {
            "baseUrl": self.settings["base_url"],
            "badgeBaseUrl": self.get_badge_base_url(),
            "logoUrl": self.static_url("logo.svg"),
            "logoWidth": "320px",
            "repoProviders": repoproviders_display_config,
            "runningEnvironmentCount": running_environment_count,
            "aboutMessage": self.settings["about_message"],
            "bannerHtml": self.settings["banner_message"],
            "binderVersion": binder_version,
        }
        self.render_template(
            "page.html",
            page_config=self.page_config,
            extra_footer_scripts=self.settings["extra_footer_scripts"],
            opengraph_title=self.opengraph_title,
        )


class RepoLaunchUIHandler(UIHandler):
    """
    Responds to /v2/ launch URLs only

    Forwards to UIHandler, but puts out an opengraph_title for social previews
    """

    def initialize(self, repo_provider):
        self.repo_provider = repo_provider
        return super().initialize()

    @authenticated
    async def get(self, provider_id, _escaped_spec):
        prefix = "/v2/" + provider_id
        spec = self.get_spec_from_request(prefix)

        build_token = jwt.encode(
            {
                "exp": int(time.time()) + self.settings["build_token_expires_seconds"],
                "aud": f"{provider_id}/{spec}",
                "origin": self.token_origin(),
            },
            key=self.settings["build_token_secret"],
            algorithm="HS256",
        )
        self.page_config["buildToken"] = build_token
        self.opengraph_title = (
            f"{self.repo_provider.display_config['displayName']}: {spec}"
        )
        return await super().get()


class LegacyRedirectHandler(BaseHandler):
    """Redirect handler from legacy Binder"""

    @authenticated
    def get(self, user, repo, urlpath=None):
        url = f"/v2/gh/{user}/{repo}/master"
        if urlpath is not None and urlpath.strip("/"):
            url = url_concat(url, dict(urlpath=urlpath))
        self.redirect(url)

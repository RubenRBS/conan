import fnmatch
import json
import os
from urllib.parse import urlparse

import requests

from conan.api.model import Remote, LOCAL_RECIPES_INDEX
from conan.api.output import ConanOutput
from conan.internal.cache.home_paths import HomePaths
from conan.internal.conan_app import ConanApp
from conans.client.rest_client_local_recipe_index import add_local_recipes_index_remote, \
    remove_local_recipes_index_remote
from conan.internal.api.remotes.localdb import LocalDB
from conan.errors import ConanException
from conans.util.files import save, load

CONAN_CENTER_CATALOG_NAME = "conan-center-catalog"


class AuditAPI:
    """
    This class provides the functionality to scan references for vulnerabilities.
    """

    def __init__(self, conan_api):
        self.conan_api = conan_api
        self._home_folder = conan_api.home_folder
        self._providers_path = os.path.join(self._home_folder, "audit_providers.json")

    def scan(self, deps_graph, provider):
        """
        Scan a given recipe for vulnerabilities in its dependencies.
        """
        refs = list(set(f"{node.ref.name}/{node.ref.version}" for node in deps_graph.nodes[1:]))

        # ConanOutput().info(f"Requesting vulnerability information for: {', '.join(refs)}")

        return provider.get_cves(refs)

    def list(self, reference, provider):
        """
        List the vulnerabilities of the given reference.
        """
        # ConanOutput().info(f"Requesting vulnerability information for: {reference}")

        return provider.get_cves([reference])

    def get_provider(self, provider_name):
        """
        Get the provider by name.
        """
        if not os.path.exists(self._providers_path):
            default_providers = {
                CONAN_CENTER_CATALOG_NAME: {
                    "url": "http://conancenter-stg-api.jfrog.team/api/v1/query",
                    "type": "conan-center-proxy",
                }
            }
            save(self._providers_path, json.dumps(default_providers))

        # TODO: More work remains to be done here, hardcoded for now for testing
        providers = json.loads(load(self._providers_path))
        if provider_name not in providers:
            raise ConanException(f"Provider '{provider_name}' not found: {json.dumps(providers)}")

        provider_data = providers[provider_name]
        provider_cls = {
            # TODO: Temp names, find better ones (specially, no mention of catalog)
            "conan-center-proxy": _ConanProxyProvider,
            "private": _PrivateProvider
        }.get(provider_data["type"])

        return provider_cls(provider_name, provider_data)

    # TODO: See if token should be optional
    def add_provider(self, name, url, provider_type, token=None):
        """
        Add a provider.
        """
        if self.get_provider(name):
            raise ConanException(f"Provider '{name}' already exists")

        providers = json.loads(load(self._providers_path))
        providers[name] = {
            "name": name,
            "url": url,
            "type": provider_type
        }
        if token:
            # TODO: Store the token in a different file/place
            providers[name]["token"] = token
        save(self._providers_path, json.dumps(providers))


    # TODO: Should this be a provider, or just its name?
    #   Do we want users to call get_provider beforehand or should we handle it here?
    def auth_provider(self, provider, token):
        """
        Authenticate a provider.
        """
        # TODO: Store the token in a different file/place
        if not provider:
            raise ConanException("Provider not found")

        providers = json.loads(load(self._providers_path))

        assert provider.name in providers
        # TODO: Store this somewhere else
        providers[provider.name]["token"] = token
        save(self._providers_path, json.dumps(providers))



# TODO: Think if providers are classes that implement get_cves,
#  or just a function and the discrimination is done in the AuditAPI
class _ConanProxyProvider:
    def __init__(self, name, provider_data):
        self.name = name
        self.url = provider_data["url"]
        self.token = provider_data.get("token")

    def get_cves(self, refs):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        result = {"data": {}}

        for ref in refs:
            ConanOutput().info(f"Requesting vulnerability info for: {ref}")
            response = requests.post(
                self.url,
                headers=headers,
                json={
                    "reference": ref,
                },
            )
            if response.status_code == 200:
                result["data"].update(response.json()["data"])
            elif response.status_code == 403:
                # TODO: How to report auth error to the user
                ConanOutput().error(f"Authentication error: {response.status_code}")
                break
            elif response.status_code == 429:
                # TODO: How to report ratelimit to the user
                msg = "Rate limit exceeded. Results may be incomplete."
                if not self.token:
                    msg += "\nPlease go to https://conancenter-stg-api.jfrog.team/ to register for a token to increase the rate limit."
                ConanOutput().warning(msg)
                break
            elif response.status_code == 500:
                # TODO: How to report internal server error to the user
                ConanOutput().error(f"Internal server error: {response.status_code}")
                break
            else:
                ConanOutput().error(f"Failed to get vulnerabilities for {ref}: {response.status_code}")
                ConanOutput().error(response.text)
        # TODO: Normalize this result so that every provider returns the same format
        return result

class _PrivateProvider:
    def __init__(self, name, provider_data):
        self.name = name
        self.url = provider_data["url"]
        self.token = provider_data.get("token")

    def get_cves(self, refs):
        pass

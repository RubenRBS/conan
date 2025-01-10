import fnmatch
import json
import os
from urllib.parse import urlparse

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

        ConanOutput().info(f"Requesting vulnerability information for: {', '.join(refs)}")

        return provider.get_cves(refs)

    def list(self, reference, provider):
        """
        List the vulnerabilities of the given reference.
        """
        ConanOutput().info(f"Requesting vulnerability information for: {reference}")

        return provider.get_cves([reference])

    def get_provider(self, provider_name):
        """
        Get the provider by name.
        """
        if not os.path.exists(self._providers_path):
            default_providers = [
                {
                    "name": CONAN_CENTER_CATALOG_NAME,
                    "url": "https://conan-center-catalog.jfrog.io/api/v1",
                    "type": "conan-center-proxy"
                }
            ]
            save(self._providers_path, json.dumps(default_providers))
         # TODO: More

        class CatalogProxyProvider:
            def __init__(self):
                pass

            def get_cves(self, refs):
                return []

        # TODO: more
        return CatalogProxyProvider()

    # TODO: See if token should be optional
    def add_provider(self, name, url, provider_type, token=None):
        """
        Add a provider.
        """
        if self.get_provider(name):
            raise ConanException(f"Provider '{name}' already exists")

        providers = json.loads(load(self._providers_path))
        new_provider_data = {
            "name": name,
            "url": url,
            "type": provider_type
        }
        if token:
            new_provider_data["token"] = token
        providers.append(new_provider_data)
        save(self._providers_path, json.dumps(providers))
        # TODO: Store the token in a different file/place


    # TODO: Should this be a provider, or just its name?
    #   Do we want users to call get_provider beforehand or should we handle it here?
    # TODO: Is this even an api method? Or should the command handle it directly?
    def auth_provider(self, provider, token):
        """
        Authenticate a provider.
        """
        pass
        # TODO: Store the token in a different file/place

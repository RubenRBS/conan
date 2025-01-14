import fnmatch
import json
import os
import textwrap
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
from conans.model.recipe_ref import RecipeReference
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
        self._provider_cls = {
            # TODO: Temp names, find better ones (specially, no mention of catalog)
            "conan-center-proxy": _ConanProxyProvider,
            "private": _PrivateProvider
        }

    def scan(self, deps_graph, provider):
        """
        Scan a given recipe for vulnerabilities in its dependencies.
        """
        refs = list(set(f"{node.ref.name}/{node.ref.version}" for node in deps_graph.nodes[1:]))
        return provider.get_cves(refs)

    def list(self, reference, provider):
        """
        List the vulnerabilities of the given reference.
        """
        ref = RecipeReference.loads(reference)
        ref.validate_ref()
        return provider.get_cves([reference])

    def get_provider(self, provider_name):
        """
        Get the provider by name.
        """
        # TODO: More work remains to be done here, hardcoded for now for testing
        providers = _load_providers(self._providers_path)
        if provider_name not in providers:
            raise ConanException(f"Provider '{provider_name}' not found")

        provider_data = providers[provider_name]
        provider_cls = self._provider_cls.get(provider_data["type"])

        return provider_cls(provider_name, provider_data)

    def get_providers(self):
        """
        Get all available providers.
        """
        providers = _load_providers(self._providers_path)
        result = []
        for name, provider_data in providers.items():
            provider_cls = self._provider_cls.get(provider_data["type"])
            result.append(provider_cls(name, provider_data))
        return result

    # TODO: See if token should be optional
    def add_provider(self, name, url, provider_type, token=None):
        """
        Add a provider.
        """
        providers = _load_providers(self._providers_path)
        if name in providers:
            raise ConanException(f"Provider '{name}' already exists")

        if provider_type not in self._provider_cls:
            raise ConanException(f"Provider type '{provider_type}' not found")

        # TODO: Validate data
        providers[name] = {
            "name": name,
            "url": url,
            "type": provider_type
        }
        if token:
            # TODO: Store the token in a different file/place
            providers[name]["token"] = token
        _save_providers(self._providers_path, providers)

    # TODO: Should this be a provider, or just its name?
    #   Do we want users to call get_provider beforehand or should we handle it here?
    def auth_provider(self, provider, token):
        """
        Authenticate a provider.
        """
        # TODO: Store the token in a different file/place
        if not provider:
            raise ConanException("Provider not found")

        providers = _load_providers(self._providers_path)

        assert provider.name in providers
        # TODO: Store this somewhere else
        providers[provider.name]["token"] = token
        _save_providers(self._providers_path, providers)


def _load_providers(providers_path):
    if not os.path.exists(providers_path):
        default_providers = {
            CONAN_CENTER_CATALOG_NAME: {
                "url": "https://conancenter-stg-api.jfrog.team/api/v1/query",
                "type": "conan-center-proxy"
            }
        }
        save(providers_path, json.dumps(default_providers, indent=4))
    return json.loads(load(providers_path))

def _save_providers(providers_path, providers):
    save(providers_path, json.dumps(providers, indent=4))

# TODO: Think if providers are classes that implement get_cves,
#  or just a function and the discrimination is done in the AuditAPI
class _ConanProxyProvider:
    def __init__(self, name, provider_data):
        self.name = name
        self.url = provider_data["url"]
        self.token = provider_data.get("token")
        self._session = requests.Session()

    def get_cves(self, refs):
        if not self.token:
            raise ConanException(textwrap.dedent(f"""
                You dont have a token for the service, go register here https://conancenter-stg-api.jfrog.team/, and once you have, run:

                conan audit auth-provider {CONAN_CENTER_CATALOG_NAME} –-token=<mytoken>

                And rerun this command
            """))

        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "Authorization": f"Bearer {self.token}"}

        result = {"data": {}}

        for ref in refs:
            ConanOutput().info(f"Requesting vulnerability info for: {ref}")
            response = self._session.post(
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

                msg = "Rate limit exceeded. Results may be incomplete."
                ConanOutput().warning(msg)
                break
            elif response.status_code == 500:
                # TODO: How to report internal server error to the user
                ConanOutput().error(f"Internal server error: {response.status_code}")
                break
            else:
                ConanOutput().error(f"Failed to get vulnerabilities for {ref}: {response.status_code}")
                ConanOutput().error(response.text)
                break
        return result

class _PrivateProvider:
    def __init__(self, name, provider_data):
        self.name = name
        self.url = provider_data["url"]
        self.data = provider_data
        self._session = requests.Session()

    def get_cves(self, refs):
        result = {"data": {}}
        for ref in refs:
            response = self._get(ref)
            # TODO: Better error handling
            if "error" in response:
                result["error"] = response["error"]
                break
            result["data"].update(response["data"])
        return result

    @staticmethod
    def _build_query(ref):
        name, version = ref.split('/')
        full_query = f"""query packageVersionDetails {{
            {name}: packageVersion(name: "{name}", type: "conan", version: "{version}") {{
                version
                vulnerabilities(first: 100) {{
                    totalCount
                    edges {{
                        node {{
                            name
                            description
                            severity
                            cvss {{
                                preferredBaseScore
                            }}
                            aliases
                            advisories {{
                                name
                                ...on JfrogAdvisory {{
                                          name
                                          shortDescription
                                          fullDescription
                                          url
                                          severity
                                     }}
                                }}
                            references
                        }}
                    }}
                }}
            }}
        }}"""
        return full_query

    @staticmethod
    def _parse_error(errors, ref):
        """This function removes the errors array that comes from the catalog and returns a more user-friendly message
        if we know how to parse it, or a generic one if we don't find such one"""

        def _replace_message(message):
            if "not found" in message:
                return f"{ref} was not found in the catalog"
            return None

        error_msgs = filter(bool, [_replace_message(error["message"]) for error in errors])
        return {"details": next(error_msgs, "Unknown error")}

    def _get(self, ref):
        full_query = self._build_query(ref)
        try:
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
            if self.data.get("token"):
                headers["Authorization"] = f"Bearer {self.data['token']}"
            elif self.data.get("user") and self.data.get("password"):
                headers["Authorization"] = f"Basic {self.data['user']}:{self.data['password']}"

            response = self._session.post(
                self.url,
                headers=headers,
                json={
                    "query": textwrap.dedent(full_query)
                }
            )
            # Raises if some HTTP error was found
            response.raise_for_status()
        except:
            return {"error": {"details": "Something went wrong"}}

        response_json = response.json()
        # filter the extensions key with graphql data
        response_json.pop('extensions', None)

        if "errors" in response_json:
            return {"error": self._parse_error(response_json["errors"], ref)}
        return response_json

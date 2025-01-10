import json
import os
from collections import OrderedDict

from conan.api.conan_api import ConanAPI
from conan.api.input import UserInput
from conan.api.model import Remote, LOCAL_RECIPES_INDEX
from conan.api.output import cli_out_write, Color, ConanOutput
from conan.cli import make_abs_path
from conan.cli.args import common_graph_args, validate_common_graph_args
from conan.cli.command import conan_command, conan_subcommand, OnceArgument
from conan.cli.commands.list import remote_color, error_color, recipe_color, \
    reference_color
from conan.cli.printers import print_profiles
from conan.cli.printers.graph import print_graph_basic
from conan.errors import ConanException
from conans.client.rest.remote_credentials import RemoteCredentials


def _add_provider_arg(subparser):
    subparser.add_argument("-p", "--provider", help="Provider to use for scanning")


@conan_subcommand(formatters={"text": cli_out_write, "json": cli_out_write})
def audit_scan(conan_api: ConanAPI, parser, subparser, *args):
    """
    Scan a given recipe for vulnerabilities in its dependencies.
    """
    common_graph_args(subparser)
    # TODO: Might not be needed?
    parser.add_argument("--build-require", action='store_true', default=False,
                        help='Whether the provided path is a build-require')
    _add_provider_arg(subparser)
    args = parser.parse_args(*args)

    # This comes from install command

    validate_common_graph_args(args)
    # basic paths
    cwd = os.getcwd()
    path = conan_api.local.get_conanfile_path(args.path, cwd, py=None) if args.path else None

    # Basic collaborators: remotes, lockfile, profiles
    remotes = conan_api.remotes.list(args.remote) if not args.no_remote else []
    overrides = eval(args.lockfile_overrides) if args.lockfile_overrides else None
    lockfile = conan_api.lockfile.get_lockfile(lockfile=args.lockfile, conanfile_path=path, cwd=cwd,
                                               partial=args.lockfile_partial, overrides=overrides)
    profile_host, profile_build = conan_api.profiles.get_profiles_from_args(args)
    print_profiles(profile_host, profile_build)

    # Graph computation (without installation of binaries)
    gapi = conan_api.graph
    if path:
        deps_graph = gapi.load_graph_consumer(path, args.name, args.version, args.user, args.channel,
                                              profile_host, profile_build, lockfile, remotes,
                                              args.update, is_build_require=args.build_require)
    else:
        deps_graph = gapi.load_graph_requires(args.requires, args.tool_requires, profile_host,
                                              profile_build, lockfile, remotes, args.update)
    print_graph_basic(deps_graph)
    deps_graph.report_graph_error()

    if deps_graph.error:
        return {"error": deps_graph.error}

    provider = conan_api.audit.get_provider(args.provider)
    vulnerabilities = conan_api.audit.scan(deps_graph, provider)

    return vulnerabilities


@conan_subcommand
def audit_list(conan_api: ConanAPI, parser, subparser, *args):
    """
    List the vulnerabilities of the given reference.
    """
    subparser.add_argument("reference", help="Reference to list vulnerabilities for")
    _add_provider_arg(subparser)
    args = parser.parse_args(*args)

    provider = conan_api.audit.get_provider(args.provider)
    vulnerabilities = conan_api.audit.list(args.reference, provider)

    return vulnerabilities


@conan_subcommand()
def audit_add_provider(conan_api, parser, subparser, *args):
    """
    Add a provider.
    """
    subparser.add_argument("name", help="Provider name to add")
    subparser.add_argument("url", help="Provider URL to add")
    subparser.add_argument("type", help="Provider type to add", choices=["catalog", "private"])  # TODO: Temp names
    subparser.add_argument("-t", "--token", help="Provider token")
    args = parser.parse_args(*args)

    if not args.token:
        user_input = UserInput(conan_api.config.get("core:non_interactive"))
        ConanOutput().write(f"Please enter a token for {args.name} the provider: ")
        token = user_input.get_password()
    else:
        token = args.token

    conan_api.audit.add_provider(args.name, args.url, args.type, token)


@conan_subcommand()
def audit_auth_provider(conan_api, parser, subparser, *args):
    """
    Authenticate on a provider
    """
    subparser.add_argument("name", help="Provider name to authenticate")
    subparser.add_argument("-t", "--token", help="Provider token to authenticate")
    args = parser.parse_args(*args)
    if not args.token:
        user_input = UserInput(conan_api.config.get("core:non_interactive"))
        ConanOutput().write(f"Please enter a token for the {args.name} provider: ")
        token = user_input.get_password()
    else:
        token = args.token

    provider = conan_api.audit.get_provider(args.name)
    conan_api.audit.auth_provider(provider, token)


@conan_command(group="Security")
def audit(conan_api, parser, *args):
    """
    Find vulnerabilities in your dependencies.
    """

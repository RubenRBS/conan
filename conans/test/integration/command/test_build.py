import json

from conans.test.assets.genconanfile import GenConanfile
from conans.test.utils.tools import TestClient


def test_build_cmd_deploy_generators():
    """
    Test that "conan build --deployer/--generators" args work
    """
    c = TestClient()
    c.save({"dep/conanfile.py": GenConanfile("dep", "1.0"),
            "pkg/conanfile.py": GenConanfile("pkg", "1.0").with_settings("build_type")
                                                          .with_requires("dep/1.0")})
    c.run("create dep")
    c.run("build pkg --deployer=full_deploy --deployer-folder=./myfolder -g=CMakeDeps")
    cmake = c.load("pkg/dep-release-data.cmake")
    current_folder = c.current_folder.replace("\\", "/")
    path = f'{current_folder}/myfolder/full_deploy/host/dep/1.0'
    assert f'set(dep_PACKAGE_FOLDER_RELEASE "{path}")' in cmake


def test_build_return_deps_graph():
    c = TestClient(light=True)
    c.save({"dep/conanfile.py": GenConanfile("dep", "1.0"),
            "pkg/conanfile.py": GenConanfile("pkg", "1.0").with_requires("dep/1.0")})

    c.run("export dep")
    c.run("build pkg -b=missing --format=json", redirect_stdout="output.json")
    graph = json.loads(c.load("output.json"))
    assert graph["graph"]["nodes"]["1"]["ref"] == "dep/1.0#6a99f55e933fb6feeb96df134c33af44"

import os
import textwrap

import pytest

from conan.test.assets.genconanfile import GenConanfile
from conan.test.utils.tools import TestClient


def test_component_error():
    # https://github.com/conan-io/conan/issues/12027
    c = TestClient()
    t1 = textwrap.dedent("""
        from conan import ConanFile

        class t1Conan(ConanFile):
            name = "t1"
            version = "0.1.0"
            package_type = "static-library"

            def package_info(self):
                self.cpp_info.components["comp1"].set_property("cmake_target_name", "t1::comp1")
                self.cpp_info.components["comp2"].set_property("cmake_target_name", "t1::comp2")
        """)
    t2 = textwrap.dedent("""
        from conan import ConanFile

        class t2Conan(ConanFile):
            name = "t2"
            version = "0.1.0"
            requires = "t1/0.1.0"
            package_type = "shared-library"

            def package_info(self):
                self.cpp_info.requires.append("t1::comp1")
        """)
    t3 = textwrap.dedent("""
        from conan import ConanFile

        class t3Conan(ConanFile):
            name = "t3"
            version = "0.1.0"
            requires = "t2/0.1.0"
            package_type = "application"
            generators = "CMakeDeps"
            settings = "os", "arch", "compiler", "build_type"
        """)

    c.save({"t1/conanfile.py": t1,
            "t2/conanfile.py": t2,
            "t3/conanfile.py": t3})
    c.run("create t1")
    c.run("create t2")
    c.run("install t3")

    arch = c.get_default_host_profile().settings['arch']
    assert 'list(APPEND t2_FIND_DEPENDENCY_NAMES )' in c.load(f"t3/t2-release-{arch}-data.cmake")
    assert not os.path.exists(os.path.join(c.current_folder, "t3/t1-config.cmake"))

def test_verify_get_property_check_type():
    c = TestClient(light=True)
    conanfile = textwrap.dedent("""
        from conan import ConanFile
        class HelloConan(ConanFile):
            name = "hello"
            version = "0.1"
            def package_info(self):
                self.cpp_info.set_property("test_property", "foo")
                self.cpp_info.get_property("test_property", check_type=list)
        """)
    c.save({"conanfile.py": conanfile})
    c.run("create .", assert_error=True)
    assert 'The expected type for test_property is "list", but "str" was found' in c.out


@pytest.mark.parametrize("component", [True, False])
def test_unused_requirement(component):
    """ Requires should include all listed requirements
        This error is known when creating the package if the requirement is consumed.
    """

    t = TestClient(light=True)
    conanfile = textwrap.dedent(f"""
        from conan import ConanFile
        class Consumer(ConanFile):
            name = "wrong"
            version = "version"
            requires = "top/version", "top2/version"

            def package_info(self):
                self.cpp_info{'.components["foo"]' if component else ''}.requires = ["top::other"]
    """)
    t.save({"top/conanfile.py": GenConanfile().with_package_info({"components": {"cmp1": {"libs": ["top_cmp1"]}}}),
            "conanfile.py": conanfile})
    t.run('create top --name=top --version=version')
    t.run('create top --name=top2 --version=version')
    t.run('create .', assert_error=True)
    assert "ERROR: wrong/version: Required package 'top2' not in component 'requires" in t.out


@pytest.mark.parametrize("component", [True, False])
def test_wrong_requirement(component):
    """ If we require a wrong requirement, we get a meaninful error.
        This error is known when creating the package if the requirement is not there.
    """
    t = TestClient(light=True)
    conanfile = textwrap.dedent(f"""
        from conan import ConanFile
        class Consumer(ConanFile):
            name = "wrong"
            version = "version"
            requires = "top/version"

            def package_info(self):
                self.cpp_info{'.components["foo"]' if component else ''}.requires =  ["top::cmp1", "other::other"]
    """)
    t.save({"top/conanfile.py": GenConanfile().with_package_info({"components": {"cmp1": {"libs": ["top_cmp1"]}}}),
            "conanfile.py": conanfile})
    t.run('create top --name=top --version=version')
    t.run('create .', assert_error=True)
    if component:
        assert "ERROR: wrong/version: required component package 'other::' (required from component 'foo') not in dependencies" in t.out
    else:
        assert "ERROR: wrong/version: required component package 'other::' not in dependencies" in t.out


@pytest.mark.parametrize("component", [True, False])
def test_missing_internal(component):
    consumer = textwrap.dedent(f"""
        from conan import ConanFile

        class Recipe(ConanFile):
            def package_info(self):
                self.cpp_info{'.components["foo"]' if component else ''}.requires = ["other", "another"]
                self.cpp_info{'.components["bar"]' if component else ''}.requires = ["other", "another"]
    """)
    t = TestClient(light=True)
    t.save({'conanfile.py': consumer})
    t.run('create . --name=wrong --version=version', assert_error=True)
    if component:
        assert ("ERROR: wrong/version: Internal components not found: 'other' (required from component 'foo'),"
                " 'another' (required from component 'foo'),"
                " 'other' (required from component 'bar'),"
                " 'another' (required from component 'bar')") in t.out
    else:
        assert "ERROR: wrong/version: Internal components not found: 'other', 'another'" in t.out

import textwrap
import unittest

import pytest

from conans.model.recipe_ref import RecipeReference
from conans.test.utils.tools import TestClient


def test_export_auto_add_to_build():
    tc = TestClient()
    tc.run("new cmake_exe -d name=pkg -d version=1.0")
    conanfile = tc.load("conanfile.py")
    conanfile += """
        def requirements(self):
            self.requires("zlib/1.2.11")
    """

    tc.save({"conanfile.py": conanfile})

    tc.run("create . --build=zlib/1.2.11")

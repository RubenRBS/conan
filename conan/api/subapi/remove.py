from conan.api.model import Remote
from conan.internal.conan_app import ConanApp, ConanBasicApp
from conans.model.package_ref import PkgReference
from conans.model.recipe_ref import RecipeReference


class RemoveAPI:

    def __init__(self, conan_api):
        self.conan_api = conan_api

    def recipe(self, ref: RecipeReference, remote: Remote=None):
        self.recipes([ref], remote)

    def recipes(self, refs, remote: Remote=None):
        # assert ref.revision, "Recipe revision cannot be None to remove a recipe"
        """Removes the recipe (or recipe revision if present) and all the packages (with all prev)"""
        app = ConanBasicApp(self.conan_api)
        if remote:
            for ref in refs:
                app.remote_manager.remove_recipe(ref, remote)
        else:
            self.all_recipes_packages(refs)
            layouts = [app.cache.recipe_layout(ref) for ref in refs]
            app.cache.remove_recipe_layouts(layouts)

    def all_recipe_packages(self, ref: RecipeReference, remote: Remote = None):
        self.all_recipes_packages([ref], remote)

    def all_recipes_packages(self, refs, remote: Remote = None):
        # assert ref.revision, "Recipe revision cannot be None to remove a recipe"
        """Removes all the packages from the provided reference"""
        app = ConanBasicApp(self.conan_api)
        if remote:
            for ref in refs:
                app.remote_manager.remove_all_packages(ref, remote)
        else:
            self._remove_all_local_packages(app, refs)

    @staticmethod
    def _remove_all_local_packages(app, refs):
        prefs = []
        for ref in refs:
            pkg_ids = app.cache.get_package_references(ref, only_latest_prev=False)
            prefs.extend(pkg_ids)
        layouts = [app.cache.pkg_layout(pref) for pref in prefs]
        app.cache.remove_package_layouts(layouts)

    def package(self, pref: PkgReference, remote: Remote):
        self.packages([pref], remote)

    def packages(self, prefs, remote: Remote):
        # assert pref.ref.revision, "Recipe revision cannot be None to remove a package"
        # assert pref.revision, "Package revision cannot be None to remove a package"
        app = ConanBasicApp(self.conan_api)
        if remote:
            app.remote_manager.remove_packages(prefs, remote)
        else:
            layouts = [app.cache.pkg_layout(pref) for pref in prefs]
            app.cache.remove_package_layouts(layouts)

# SPDX-License-Identifier: BSD-2-Clause
# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os

project = "Styx"
copyright = "2025, Kudu Dynamics LLC, a Leidos Company"
author = "Styx Emulator Contributors"

repository_url = os.environ.get(
    "CI_REPOSITORY_URL", "https://github.com/styx-emulator/styx-emulator"
)

# populate .local.env with private pip index if applicable:
#
# eg.
# https://gitlab.domain.com/groups/styx/-/packages/1349
pip_index_command = os.environ.get("STYX_PIP_INDEX_CMD", "pip install styx-py-api")

# populate .local.env with private pip help page if applicable
pip_install_help_url = os.environ.get(
    "STYX_PIP_INSTALL_HELP_URL", "https://pip.pypa.io/en/stable/cli/pip_install/"
)

# get the required rust version from the source tree
with open("../../.rust-version", "r") as f:
    rust_version = f.readline()

# Current global mods:
#
# replaces all `|repository_url|` with whatever the python variable `repository_url` is
rst_prolog = f"""
.. |repository_url| replace:: {repository_url}
.. |pip-index-command| replace:: {pip_index_command}
.. |rust-version| replace:: {rust_version}
.. |pip-install-help| replace:: {pip_install_help_url}
"""

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx_mdinclude",
    "sphinxemoji.sphinxemoji",
    "sphinxcontrib.mermaid",
    "sphinx_copybutton",
    "sphinx_immaterial",
    "sphinxnotes.strike",
    "sphinx_substitution_extensions",
]

templates_path = ["_templates"]
exclude_patterns = []

sphinxemoji_style = "twemoji"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_immaterial"
html_static_path = ["_static"]
html_extra_path = ["_static"]
html_favicon = "_static/styx-emulator-favicon.png"
html_baseurl = "https://docs.styx-emulator.org/"
html_title = "Styx Documentation"

html_theme_options = {
    # "nav_title": "styx-emulator",
    "palette": [
        {
            "media": "(prefers-color-scheme: light)",
            "scheme": "default",
            "primary": "indigo",
            "accent": "light-blue",
            "toggle": {
                "icon": "material/lightbulb-outline",
                "name": "Switch to dark mode",
            },
        },
        {
            "media": "(prefers-color-scheme: dark)",
            "scheme": "slate",
            "primary": "indigo",
            "accent": "light-blue",
            "toggle": {
                "icon": "material/lightbulb",
                "name": "Switch to light mode",
            },
        },
    ],
    "repo_url": repository_url,
    "repo_name": "styx-emulator",
    # "globaltoc_depth": 1,
    "globaltoc_collapse": False,
    "globaltoc_includehidden": False,
    "icon": {
        "repo": "fontawesome/brands/github",
        "edit": "material/file-edit-outline",
        "logo": "material/memory",
    },
    # TODO: find a way to restore this old behavior we had in `sphinx-material`
    # "nav_links": [
    #     {"href": "./api/index", "internal": True, "title": "Rust API Documentation"}
    # ],
    # https://jbms.github.io/sphinx-immaterial/customization.html#themeconf-features
    "features": [
        "content.code.annotate",  # https://jbms.github.io/sphinx-immaterial/code_annotations.html
        "content.tabs.link",  # https://jbms.github.io/sphinx-immaterial/content_tabs.html#linked-tabs
        "navigation.instant",
        "navigation.sections",
        "navigation.top",
        "navigation.tracking",
        "search.highlight",
        "search.share",
        "toc.sticky",
        "toc.follow",
    ],
}

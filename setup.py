import os
from setuptools import setup, find_packages

# :==> Fill in your project data here
library_name = 'dt_authentication'
library_webpage = 'https://github.com/duckietown/lib-dt-authentication'
maintainer = 'Andrea F. Daniele'
maintainer_email = 'afdaniele@ttic.edu'
short_description = 'Python library for authentication in Duckietown using the Duckietown Token'
full_description = """
This library can be used to manipulate Duckietown Tokens.
"""
# <==: Fill in your project data here

# read project details
dt_project_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dtproject')
with open(dt_project_file, 'rt') as fin:
    project = dict(map(lambda line: line.split('='), fin.read().splitlines()))
version = project['VERSION']

# read project dependencies
dependencies_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dependencies.txt')
with open(dependencies_file, 'rt') as fin:
    dependencies = list(filter(lambda line: not line.startswith('#'), fin.read().splitlines()))

# compile description
underline = '=' * (len(library_name) + len(short_description) + 2)
description = """
{name}: {short}
{underline}

{long}
""".format(name=library_name, short=short_description, long=full_description, underline=underline)

# setup package
setup(
    name=library_name,
    author=maintainer,
    author_email=maintainer_email,
    url=library_webpage,
    install_requires=dependencies,
    package_dir={"": "include"},
    packages=find_packages('./include'),
    long_description=description,
    version=version,
    include_package_data=True
)

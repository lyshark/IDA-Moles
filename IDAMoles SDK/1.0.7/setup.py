import setuptools
from distutils.core import setup

packages = ['IDAMoles']

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='IDAMoles',
    version='1.0.7',
    author='lyshark',
    description='IDA Moles is a reverse analysis interface for IDA Pro 9.1. It controls decompilation, debugging, and other operations via standardized calls, returning POST-formatted results. It supports custom MCP server development to enhance reverse analysis efficiency and flexibility.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email='me@lyshark.com',
    url="http://moles.lyshark.com",
    python_requires=">=3.6.0",
    license="MIT Licence",
    packages=packages,
    include_package_data=True,
    platforms="any",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        # Add any dependencies here
    ],
)

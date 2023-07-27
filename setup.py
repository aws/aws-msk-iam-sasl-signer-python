#!/usr/bin/env python

#  Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""The setup script."""

from setuptools import find_packages, setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("CHANGELOG.rst") as changelog_file:
    history = changelog_file.read()

requirements = ["Click>=7.0", "boto3==1.26.125", "botocore==1.29.125"]

test_requirements = [
    "pytest==7.3.1",
    "pytest-cov==4.0.0",
    "coverage==7.2.5",
    "mock==5.0.2",
]

setup(
    author="Mohit Paliwal",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Amazon MSK Library in Python for SASL/OAUTHBEARER Auth",
    entry_points={
        "console_scripts": [
            "aws_msk_get_auth_token=aws_msk_iam_sasl_signer.cli:execute",
        ],
    },
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="aws-msk-iam-sasl-signer-python",
    name="aws-msk-iam-sasl-signer-python",
    packages=find_packages(),
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/awslabs/aws-msk-iam-sasl-signer-python",
    version="0.1.0",
    zip_safe=False,
)
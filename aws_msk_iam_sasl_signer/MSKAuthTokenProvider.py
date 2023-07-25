#  Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import base64
import logging

import boto3
import botocore.session
import pkg_resources
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import CredentialProvider, Credentials

logging.basicConfig(level=logging.INFO)

ENDPOINT_URL_TEMPLATE = "https://kafka.{}.amazonaws.com/"
DEFAULT_TOKEN_EXPIRY_SECONDS = 900
DEFAULT_STS_SESSION_NAME = "MSKSASLDefaultSession"
ACTION_TYPE = "Action"
ACTION_NAME = "kafka-cluster:Connect"
SIGNING_NAME = "kafka-cluster"
USER_AGENT_KEY = "User-Agent"
LIB_NAME = "aws-msk-iam-sasl-signer-python"


def __get_user_agent__():
    """
    Builds the user-agent

    Returns:
        str: The user-agent identifying this signer library.
    """
    return f"{LIB_NAME}/{pkg_resources.get_distribution(LIB_NAME).version}"


def __load_default_credentials__():
    """
    Loads IAM credentials from default credentials chain.

    Returns:
      :class:`botocore.credentials.Credentials` object
    """

    # Create a botocore session with default settings
    botocore_session = botocore.session.Session()

    return botocore_session.get_credentials()


def __load_credentials_from_aws_profile__(aws_profile):
    """
    Loads IAM credentials from named aws profile.

    Parameters:
    - aws_profile (str): The name of the AWS profile to use for the session.

    Returns:
      :class:`botocore.credentials.Credentials` object
    """

    # Create a botocore session with an aws named profile
    botocore_session = botocore.session.Session(profile=aws_profile)

    return botocore_session.get_credentials()


def __load_credentials_from_aws_role_arn__(
    role_arn, sts_session_name=DEFAULT_STS_SESSION_NAME
):
    """
    Loads IAM credentials from an aws role arn. At each refresh it creates a
    new sts client with a global endpoint. If this is not the desired
    behavior, please use your own credentials provider.

    Parameters:
    - role_arn (str): The ARN of the IAM role to assume for the session.
    - sts_session_name (str): The sts session name for assumed role's session.

    Returns:
      :class:`botocore.credentials.Credentials` object
    """

    # Create sts client
    sts_client = boto3.client("sts", config=Config())

    assumed_role = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName=sts_session_name
    )
    assumed_role_credentials = assumed_role["Credentials"]
    return Credentials(
        assumed_role_credentials["AccessKeyId"],
        assumed_role_credentials["SecretAccessKey"],
        assumed_role_credentials["SessionToken"],
    )


def __load_credentials_from_aws_credentials_provider__(
    aws_credentials_provider
):
    """
    Loads IAM credentials from aws credentials provider.

    Parameters: - aws_credentials_provider (
    botocore.credentials.CredentialProvider): The aws credential provider.

    Returns:
      :class:`botocore.credentials.Credentials` object
    """

    # Load credentials
    return aws_credentials_provider.load()


def generate_auth_token(region):
    """
    Generates an base64-encoded signed url as auth token to authenticate
    with an Amazon MSK cluster using default IAM credentials.

    Args:
        region (str): The AWS region where the cluster is located.
    Returns:
        str: A base64-encoded authorization token.
    """

    # Load credentials
    aws_credentials = __load_default_credentials__()

    return __construct_auth_token(region, aws_credentials)


def generate_auth_token_from_profile(region, aws_profile):
    """
    Generates an base64-encoded signed url as auth token to authenticate
    with an Amazon MSK cluster using IAM credentials from an aws named
    profile.

    Args:
        region (str): The AWS region where the cluster is located.
        aws_profile (str): The name of the AWS profile to use.
    Returns:
        str: A base64-encoded authorization token.
    """
    # Load credentials
    aws_credentials = __load_credentials_from_aws_profile__(aws_profile)

    return __construct_auth_token(region, aws_credentials)


def generate_auth_token_from_role_arn(
    region, role_arn, sts_session_name=DEFAULT_STS_SESSION_NAME
):
    """
    Generates an base64-encoded signed url as auth token to authenticate
    with an Amazon MSK cluster using IAM Credentials by assuming the
    provided role arn.

    Args: region (str): The AWS region where the cluster is located.
    role_arn (str): The ARN of the IAM role to assume for the session.
    sts_session_name (str): The sts session name for assumed role's session.
    Optional. Returns: str: A base64-encoded authorization token.
    """
    # Load credentials
    aws_credentials = __load_credentials_from_aws_role_arn__(role_arn,
                                                             sts_session_name)

    return __construct_auth_token(region, aws_credentials)


def generate_auth_token_from_credentials_provider(region,
                                                  aws_credentials_provider):
    """
    Generates an base64-encoded signed url as auth token to authenticate
    with an Amazon MSK cluster using IAM Credentials provided by a
    credentials provider.

    Args: region (str): The AWS region where the cluster is located.
    aws_credentials_provider (botocore.credentials.CredentialProvider): The
    credentials provider that provides IAM credentials. Returns: str: A
    base64-encoded authorization token.
    """
    # Check the type of the credentials provider
    if not isinstance(aws_credentials_provider, CredentialProvider):
        raise TypeError(
            "aws_credentials_provider should be of type "
            "botocore.credentials.CredentialProvider "
        )

    # Load credentials
    aws_credentials = __load_credentials_from_aws_credentials_provider__(
        aws_credentials_provider
    )

    return __construct_auth_token(region, aws_credentials)


def __construct_auth_token(region, aws_credentials):
    """
    Private function that constructs the authorization token using IAM
    Credentials.

    Args: region (str): The AWS region where the cluster is located.
    aws_credentials (dict): The credentials to be used to generate signed
    url. Returns: str: A base64-encoded authorization token.
    """
    # Extract endpoint URL
    endpoint_url = ENDPOINT_URL_TEMPLATE.format(region)

    # Set up resource path and query parameters
    query_params = {ACTION_TYPE: ACTION_NAME}

    # Create SigV4 instance
    sig_v4 = SigV4QueryAuth(
        aws_credentials, SIGNING_NAME, region,
        expires=DEFAULT_TOKEN_EXPIRY_SECONDS
    )

    # Create request with url and parameters
    request = AWSRequest(method="GET", url=endpoint_url, params=query_params)

    # Add auth to the request and prepare the request
    sig_v4.add_auth(request)
    query_params = {USER_AGENT_KEY: __get_user_agent__()}
    request.params = query_params
    prepped = request.prepare()

    # Get the signed url
    signed_url = prepped.url

    # TODO : Remove logging here and add caller identity logging
    logging.debug("Signed URL: %s", signed_url)

    # Base 64 encode and remove the padding from the end
    signed_url_bytes = signed_url.encode("utf-8")
    base64_bytes = base64.urlsafe_b64encode(signed_url_bytes)
    base64_encoded_signed_url = base64_bytes.decode("utf-8").rstrip("=")
    return base64_encoded_signed_url

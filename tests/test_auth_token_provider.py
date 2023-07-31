#  Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Tests for `aws-msk-iam-sasl-signer-python` package."""
import base64
import unittest
from datetime import datetime
from unittest import mock
from urllib.parse import parse_qs, urlparse

import botocore.credentials
from botocore.credentials import CredentialProvider, Credentials
from botocore.exceptions import ParamValidationError, ProfileNotFound
from click.testing import CliRunner

from aws_msk_iam_sasl_signer import cli
from aws_msk_iam_sasl_signer.MSKAuthTokenProvider import (
    ACTION_NAME, ACTION_TYPE, DEFAULT_STS_SESSION_NAME,
    DEFAULT_TOKEN_EXPIRY_SECONDS, LIB_NAME,
    __load_credentials_from_aws_credentials_provider__,
    __load_credentials_from_aws_profile__,
    __load_credentials_from_aws_role_arn__, __load_default_credentials__,
    generate_auth_token, generate_auth_token_from_credentials_provider,
    generate_auth_token_from_profile, generate_auth_token_from_role_arn)


class TestCredentialProvider(CredentialProvider):
    __test__ = False

    def load(self):
        return Credentials(
            access_key="MOCK_AWS_ACCESS_KEY",
            secret_key="MOCK_AWS_SECRET_KEY",
            token="MOCK_AWS_TOKEN",
        )


class TestGenerateAuthToken(unittest.TestCase):
    def setUp(self):
        self.region = "us-west-2"
        self.aws_profile = "dev"
        self.role_arn = "arn:aws:iam::123456789012:role/MyRole"
        self.endpoint_url = "https://kafka.us-west-2.amazonaws.com/"
        self.mock_access_key = "MOCK_AWS_ACCESS_KEY"
        self.mock_secret_key = "MOCK_AWS_SECRET_KEY"
        self.mock_token = "MOCK_AWS_TOKEN"

    def test_generate_auth_token_with_invalid_credentials_type(self):
        aws_credentials = {"AccessKeyId": self.mock_access_key}
        expected_error_message = "aws_credentials_provider should be of " \
                                 "type botocore.credentials.CredentialProvider"

        with self.assertRaisesRegex(TypeError, expected_error_message):
            generate_auth_token_from_credentials_provider(self.region,
                                                          aws_credentials)

    def test_generate_auth_token_with_invalid_credentials_content(self):
        expected_error_message = "missing 1 required positional argument: " \
                                 "'secret_key'"

        with self.assertRaisesRegex(TypeError, expected_error_message):
            Credentials(self.mock_access_key)

    @mock.patch("botocore.session")
    def test_load_default_credentials(self, mock_session):
        mock_botocore_session = mock_session.Session.return_value
        mock_botocore_session.get_credentials.return_value = Credentials(
            self.mock_access_key, self.mock_secret_key
        )

        creds = __load_default_credentials__()

        mock_session.Session.assert_called_once_with()
        mock_botocore_session.get_credentials.assert_called_once()

        self.assertIsInstance(creds, Credentials)
        self.assertEqual(creds.access_key, self.mock_access_key)
        self.assertEqual(creds.secret_key, self.mock_secret_key)

    @mock.patch("botocore.session")
    def test_load_credentials_with_aws_profile(self, mock_session):
        mock_botocore_session = mock_session.Session.return_value
        mock_botocore_session.get_credentials.return_value = Credentials(
            self.mock_access_key, self.mock_secret_key
        )

        creds = __load_credentials_from_aws_profile__(self.aws_profile)

        mock_session.Session.assert_called_once_with(profile=self.aws_profile)
        mock_botocore_session.get_credentials.assert_called_once()

        self.assertIsInstance(creds, Credentials)
        self.assertEqual(creds.access_key, self.mock_access_key)
        self.assertEqual(creds.secret_key, self.mock_secret_key)

    @mock.patch("botocore.session")
    def test_load_credentials_with_missing_profile(self, mock_session):
        mock_session.Session.side_effect = ProfileNotFound(profile="missing")

        expected_error_message = "The config profile \\(missing\\) could not" \
                                 " be found"

        with self.assertRaisesRegex(ProfileNotFound, expected_error_message):
            __load_credentials_from_aws_profile__("missing")

        mock_session.Session.assert_called_once_with(profile="missing")

    @mock.patch("boto3.client")
    def test_load_credentials_with_valid_arn(self, mock_boto_client):
        mock_credentials = {
            "AccessKeyId": self.mock_access_key,
            "SecretAccessKey": self.mock_secret_key,
            "SessionToken": self.mock_token,
        }
        mock_sts_client = mock_boto_client.return_value
        mock_sts_client.assume_role.return_value = {
            "Credentials": mock_credentials}
        creds = __load_credentials_from_aws_role_arn__(self.role_arn)
        mock_sts_client.assume_role.assert_called_with(
            RoleArn=self.role_arn, RoleSessionName=DEFAULT_STS_SESSION_NAME
        )

        self.assertIsInstance(creds, Credentials)
        self.assertEqual(creds.access_key, self.mock_access_key)
        self.assertEqual(creds.secret_key, self.mock_secret_key)
        self.assertEqual(creds.token, self.mock_token)

    @mock.patch("boto3.client")
    def test_load_credentials_with_invalid_arn(self, mock_boto_client):
        mock_sts_client = mock.Mock()
        mock_sts_client.assume_role.side_effect = ParamValidationError(
            report=None)
        mock_boto_client.return_value = mock_sts_client
        with self.assertRaises(ParamValidationError):
            __load_credentials_from_aws_role_arn__("invalid-arn")
        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn="invalid-arn", RoleSessionName=DEFAULT_STS_SESSION_NAME
        )

    @mock.patch("boto3.client")
    def test_load_credentials_with_valid_arn_and_session_name(self,
                                                              mock_boto):
        mock_credentials = {
            "AccessKeyId": self.mock_access_key,
            "SecretAccessKey": self.mock_secret_key,
            "SessionToken": self.mock_token,
        }
        mock_sts_client = mock_boto.return_value
        mock_sts_client.assume_role.return_value = {
            "Credentials": mock_credentials}
        creds = __load_credentials_from_aws_role_arn__(self.role_arn,
                                                       "MY-SESSION")
        mock_sts_client.assume_role.assert_called_with(
            RoleArn=self.role_arn, RoleSessionName="MY-SESSION"
        )

        self.assertIsInstance(creds, Credentials)
        self.assertEqual(creds.access_key, self.mock_access_key)
        self.assertEqual(creds.secret_key, self.mock_secret_key)
        self.assertEqual(creds.token, self.mock_token)

    def test_load_credentials_with_credentials_provider(self):
        test_credential_provider = TestCredentialProvider()

        creds = __load_credentials_from_aws_credentials_provider__(
            test_credential_provider
        )

        self.assertIsInstance(creds, Credentials)
        self.assertEqual(creds.access_key, self.mock_access_key)
        self.assertEqual(creds.secret_key, self.mock_secret_key)
        self.assertEqual(creds.token, self.mock_token)

    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_default_credentials__"
    )
    def test_generate_auth_token(self, mock_load_credentials):
        mock_credentials = Credentials(
            self.mock_access_key, self.mock_secret_key, self.mock_token
        )
        mock_load_credentials.return_value = mock_credentials
        auth_token = generate_auth_token(self.region)

        self.assertTokenIsAsExpected(auth_token)

    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_credentials_from_aws_profile__"
    )
    def test_generate_auth_token_from_aws_profile(self, mock_load_credentials):
        mock_credentials = Credentials(
            self.mock_access_key, self.mock_secret_key, self.mock_token
        )
        mock_load_credentials.return_value = mock_credentials
        auth_token = generate_auth_token_from_profile(self.region,
                                                      self.aws_profile)

        self.assertTokenIsAsExpected(auth_token)

    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_credentials_from_aws_role_arn__"
    )
    def test_generate_auth_token_from_role_arn(self, mock_load_credentials):
        mock_credentials = Credentials(
            self.mock_access_key, self.mock_secret_key, self.mock_token
        )
        mock_load_credentials.return_value = mock_credentials
        auth_token = generate_auth_token_from_role_arn(self.region,
                                                       self.aws_profile)

        self.assertTokenIsAsExpected(auth_token)

    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_credentials_from_aws_credentials_provider__"
    )
    def test_generate_auth_token_with_credentials_provider(self,
                                                           load_credentials):
        mock_credentials = Credentials(
            self.mock_access_key, self.mock_secret_key, self.mock_token
        )
        load_credentials.return_value = mock_credentials
        credential_provider = botocore.credentials.ContainerProvider()
        auth_token = generate_auth_token_from_credentials_provider(
            self.region, credential_provider
        )

        self.assertTokenIsAsExpected(auth_token)

    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_credentials_from_aws_credentials_provider__"
    )
    def test_generate_auth_token_with_empty_credentials(self,
                                                        load_credentials):
        mock_credentials = Credentials("", "")
        load_credentials.return_value = mock_credentials
        credential_provider = botocore.credentials.ContainerProvider()

        expected_error_message = "AWS Credentials can not be empty"

        with self.assertRaisesRegex(ValueError, expected_error_message):
            generate_auth_token_from_credentials_provider(
                self.region, credential_provider
            )

    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_default_credentials__"
    )
    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_credentials_from_aws_profile__"
    )
    @mock.patch(
        "aws_msk_iam_sasl_signer.MSKAuthTokenProvider"
        ".__load_credentials_from_aws_role_arn__"
    )
    def test_command_line_interface(
        self, mock_load_credentials, mock_profile_credentials,
        mock_role_credentials
    ):
        mock_credentials = Credentials(
            self.mock_access_key, self.mock_secret_key, self.mock_token
        )
        mock_load_credentials.return_value = mock_credentials
        mock_profile_credentials.return_value = mock_credentials
        mock_role_credentials.return_value = mock_credentials

        runner = CliRunner()
        result = runner.invoke(cli.execute, ["--region", self.region])

        self.assertEqual(result.exit_code, 0)
        self.assertTokenIsAsExpected(result.output)

        result = runner.invoke(
            cli.execute,
            ["--region", self.region, "--aws-profile", self.aws_profile]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertTokenIsAsExpected(result.output)

        result = runner.invoke(
            cli.execute, ["--region", self.region, "--role-arn", self.role_arn]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertTokenIsAsExpected(result.output)

        help_result = runner.invoke(cli.execute, ["--help"])
        self.assertEqual(help_result.exit_code, 0)

    def test_command_line_interface_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli.execute)
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.return_value, None)

        result = runner.invoke(
            cli.execute,
            [
                "--region",
                self.region,
                "--aws-profile",
                self.aws_profile,
                "--role-arn",
                self.role_arn,
            ],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.return_value, None)

    def assertTokenIsAsExpected(self, auth_token):
        self.assertIsNotNone(auth_token)

        # Add padding to ensure decoding does not complain of no padding
        padded_auth_token = auth_token + "===="
        decoded_signed_url = base64.urlsafe_b64decode(
            padded_auth_token).decode("utf-8")

        self.assertTrue(decoded_signed_url.startswith(self.endpoint_url))

        parsed_url = urlparse(decoded_signed_url)
        query_params = parse_qs(parsed_url.query)

        self.assertEqual(query_params[ACTION_TYPE][0], ACTION_NAME)
        self.assertEqual(query_params["X-Amz-Algorithm"][0],
                         "AWS4-HMAC-SHA256")
        self.assertEqual(
            query_params["X-Amz-Expires"][0], str(DEFAULT_TOKEN_EXPIRY_SECONDS)
        )
        self.assertEqual(query_params["X-Amz-Security-Token"][0],
                         "MOCK_AWS_TOKEN")
        credential = query_params["X-Amz-Credential"][0]
        self.assertEqual(credential.split("/")[0], "MOCK_AWS_ACCESS_KEY")
        self.assertEqual(query_params["X-Amz-SignedHeaders"][0], "host")
        self.assertIsNotNone(query_params["X-Amz-Signature"][0])
        date_obj = datetime.strptime(query_params["X-Amz-Date"][0],
                                     "%Y%m%dT%H%M%SZ")
        self.assertTrue(date_obj < datetime.utcnow())

        self.assertTrue(query_params["User-Agent"][0].startswith(LIB_NAME))

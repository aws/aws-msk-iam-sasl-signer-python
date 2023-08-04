#  Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Console script for aws-msk-iam-sasl-signer-python."""
import sys

import click

from aws_msk_iam_sasl_signer.MSKAuthTokenProvider import (
    generate_auth_token, generate_auth_token_from_profile,
    generate_auth_token_from_role_arn)


def validate_options(ctx):
    region = ctx.params.get("region")
    aws_profile = ctx.params.get("aws_profile")
    role_arn = ctx.params.get("role_arn")

    if region is None:
        raise click.UsageError("--region must be provided.")

    if aws_profile and role_arn:
        raise click.UsageError(
            "Only one of --aws-profile and --role-arn should be provided."
        )


@click.command()
@click.option("--region", default=None, help="AWS region")
@click.option("--aws-profile", default=None, help="Name of the AWS profile")
@click.option("--role-arn", default=None, help="ARN of the role to assume")
@click.option("--sts-session-name", default=None, help="STS Session name")
@click.pass_context
def execute(ctx, region, aws_profile, role_arn, sts_session_name):
    ctx.ensure_object(dict)
    ctx.obj["region"] = region
    ctx.obj["aws_profile"] = aws_profile
    ctx.obj["role_arn"] = role_arn
    ctx.obj["sts_session_name"] = sts_session_name

    validate_options(ctx)

    if aws_profile:
        response = generate_auth_token_from_profile(region, aws_profile)
    elif role_arn:
        response = generate_auth_token_from_role_arn(region, role_arn,
                                                     sts_session_name)
    else:
        response = generate_auth_token(region)

    click.echo(response)


if __name__ == "__main__":
    try:
        sys.exit(execute(obj={}))
    except click.UsageError as e:
        click.echo(e, err=True)
        sys.exit(1)

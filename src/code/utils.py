# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import os
import hashlib
import base64
import re
import boto3
import json
from jira import JIRA, JIRAError
from botocore.exceptions import ClientError
import jira

logger = logging.getLogger('')


def validate_environments(envs):
    undefined = []

    for env in envs:
        is_defined = env in os.environ
        if not is_defined:
            undefined.append(env)
            logger.error('Environment variable %s not set', env)
    if len(undefined) > 0:
        raise UserWarning(
            "Missing environment variables: {}".format(",".join(undefined)))


def assume_role(aws_account_number, role_name, external_id=None):
    """
    Assumes the provided role in each account and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    """
    sts_client = boto3.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    parameters = {"RoleArn": 'arn:{}:iam::{}:role/{}'.format(
        partition,
        aws_account_number,
        role_name,
    ), "RoleSessionName": "SecurityScanner"}

    if external_id:
        parameters["ExternalId"] = external_id
    response = sts_client.assume_role(**parameters)

    account_session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

    session = {}
    session['session'] = account_session
    session['aws_access_key_id'] = response['Credentials']['AccessKeyId']
    session['aws_secret_access_key'] = response['Credentials']['SecretAccessKey']
    session['aws_session_token'] = response['Credentials']['SessionToken']
    return session


def update_unassigned_ticket(jira_client, issue, message):
    jira_client.assign_issue(issue, os.environ.get("JIRA_DEFAULT_ASSIGNEE"))
    issue.fields.labels.append("aws-sec-not-assigned")
    issue.update(fields={"labels": issue.fields.labels})
    jira_client.add_comment(issue, message)


def get_account_organization_tags(account):
    org_id = os.environ.get("ORG_ACCOUNT_ID")
    org_role = os.environ.get("ORG_ROLE")
    external_id = os.environ.get("EXTERNAL_ID")
    if org_role:
        session = assume_role(org_id, org_role, external_id)['session']
        org_client = session.client('organizations')
        tags = org_client.list_tags_for_resource(ResourceId=account)
        return tags
    return {}
    
# assign ticket based on Organization account


def update_jira_assignee(jira_client, issue, account):
    tags = get_account_organization_tags(account)
    merged_tags = {}
    for tag in tags['Tags']:
        merged_tags[tag['Key']] = tag['Value']
    if merged_tags.get("SecurityContactID"):
        assignee = merged_tags.get("SecurityContactID")
        try:
            jira_client.assign_issue(issue, assignee)
        except JIRAError:
            logger.warning("User {0} couldn't be assigned to {1}".format(
                assignee, jira_client))
            message = "Security responsible not in JIRA\n Id: {0}".format(
                assignee)
            update_unassigned_ticket(jira_client, issue, message)
    else:
        logger.info("Account owner could not be identified {0} - {1}".format(account,issue))
        message = "Account owner could not be identified"
        update_unassigned_ticket(jira_client, issue, message)


def get_finding_id_from(jira_ticket):
    if jira_ticket is None or jira_ticket.fields.description is None:
        logger.warning("The jira_ticket or its description is None, cannot extract finding ID.")
        return None

    description = jira_ticket.fields.description
    # Searching for regex in description
    matched = re.search(
        'Id%3D%255Coperator%255C%253AEQUALS%255C%253A([a-zA-Z0-9\\.\\-\\_\\:\\/]+)', description)
    return matched.group(1) if matched and matched.group(1) else None

def get_jira_client(secretsmanager_client,jira_instance,jira_credentials_secret):
    region = os.environ['AWS_REGION']
    jira_credentials = get_secret(secretsmanager_client, jira_credentials_secret, region)
    auth_type = jira_credentials['auth']
    jira_client = None
    if auth_type == "basic_auth":
        jira_client=JIRA("https://"+jira_instance, basic_auth=(jira_credentials['email'], jira_credentials['token']))
    else:
        jira_client=JIRA(jira_instance, token_auth=jira_credentials['token'])

    return jira_client


def get_finding_digest(finding_id):
    m = hashlib.md5()  # nosec
    m.update(finding_id.encode("utf-8"))
    one_way_digest = m.hexdigest()
    return one_way_digest


def get_jira_finding(jira_client, finding_id,project_key, issuetype_name):
    digest = get_finding_digest(finding_id)
    created_before = jira_client.search_issues(
        'Project = {0} AND issuetype = "{1}" AND (labels = aws-sec-{2})'.format(project_key, issuetype_name,digest))
    # Should only exist once
    return created_before[0] if len(created_before) > 0 else None

def get_jira_latest_updated_findings(jira_client,project_key, issuetype_name):
    return jira_client.search_issues('Project = {0} AND issuetype = "{1}" AND updated  >= -2w'.format(project_key, issuetype_name), maxResults=False)

# creates ticket based on the Security Hub finding
def create_ticket(jira_client, project_key, issuetype_name, account, region, description, resources, severity, title, id):
    digest = get_finding_digest(id)

    finding_link = "https://{0}.console.aws.amazon.com/securityhub/home?region={0}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{1}".format(
        region, id)
    issue_dict = {
        "project": {"key": project_key},
        "issuetype": {"name": issuetype_name},  
        "summary": "AWS Security Issue :: {} :: {} :: {}".format(account, region, title),
        "labels": ["aws-sec-%s" % digest],
        "priority": {"name": severity.capitalize()},
        "description": """ *What is the problem?*
        We detected a security finding within the AWS account {} you are responsible for.
        {}
        
        {}

        [Link to Security Hub finding|{}] 

        *What do I need to do with the ticket?*
        * Access the account and verify the configuration.
        Acknowledge working on ticket by moving it to "Allocated for Fix".
        Once fixed, moved to test fix so Security validates the issue is addressed.
        * If you think risk should be accepted, move it to "Awaiting Risk acceptance".
        This will require review by a Security engineer.
        * If you think is a false positive, transition it to "Mark as False Positive".
        This will get reviewed by a Security engineer and reopened/closed accordingly.
          """.format(account, resources, description, finding_link)
    }
    new_issue = jira_client.create_issue(
        fields=issue_dict)  # writes dict to jira
    return new_issue


def update_securityhub(securityhub_client, id, product_arn, status, note):
    response = securityhub_client.batch_update_findings(
        FindingIdentifiers=[
            {'Id':  id,
             'ProductArn': product_arn
             }],
        Workflow={'Status': status}, Note={
            'Text': note,
            'UpdatedBy': 'security-hub-integration'
        })
    if response.get('FailedFindings'):
        for element in response['FailedFindings']:
            logger.error("Update error - FindingId {0}".format(element["Id"]))
            logger.error(
                "Update error - ErrorCode {0}".format(element["ErrorCode"]))
            logger.error(
                "Update error - ErrorMessage {0}".format(element["ErrorMessage"]))


def is_closed(jira_client, issue):
    return issue.fields.status.name == "Resolved"


def is_suppressed(jira_client, issue):
    return issue.fields.status.name == "Risk approved" or issue.fields.status.name == "Accepted false positive"


def is_test_fix(jira_client, issue):
    return issue.fields.status.name == "Test fix"


def reopen_jira_issue(jira_client, issue):
    jira_client.transition_issue(issue, 'Reopen')


def close_jira_issue(jira_client, issue):
    status = issue.fields.status.name
    if status in ["Open"]:
        jira_client.transition_issue(issue, "Allocate for fix")
    if status in ["Open", "Allocated for fix"]:
        jira_client.transition_issue(issue, "Mark for testing")
    if status in ["Open", "Allocated for fix", "Test fix"]:
        jira_client.transition_issue(issue, "Mark as resolved", comment="Resolved automatically by security-hub-integration")
    else:
        logger.error(
            "Cannot transition issue {0} as it's either marked as closed, awaiting risk acceptance or as false positive".format(issue))


def get_secret(client, secret_arn, region_name):

    secret = None
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_arn
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(
                get_secret_value_response['SecretBinary'])
    return json.loads(secret)

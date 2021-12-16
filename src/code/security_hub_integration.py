# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import json
import os
import boto3
import sys
from jira import JIRA
import utils
from datetime import datetime, timezone

# set global logger
logger = logging.getLogger('')
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

securityhub = boto3.client('securityhub')
secretsmanager = boto3.client('secretsmanager')


def finding_parser(finding):
    account = finding["AwsAccountId"]
    description = finding["Description"]
    severity = finding["Severity"]["Label"]
    title = finding["Title"]
    finding_id = finding["Id"]
    product_arn = finding["ProductArn"]
    resources = [resource.get('Id') for resource in finding["Resources"]]
    status = finding["Workflow"]["Status"]
    recordstate = finding["RecordState"]

    return account, description, severity, title, finding_id, product_arn, resources, status, recordstate  # returns data


def create_jira(jira_client, project_key, issuetype_name, product_arn, account, region, description, resources, severity, title, id):

    resources = "Resources: %s" % resources if not "default" in product_arn else ""

    new_issue = utils.create_ticket(
        jira_client, project_key, issuetype_name, account, region, description, resources, severity, title, id)
    utils.update_securityhub(
        securityhub, id, product_arn, "NOTIFIED", 'JIRA Ticket: {0}'.format(new_issue))
    utils.update_jira_assignee(jira_client, new_issue, account)


def is_automated_check(finding):
    script_dir=os.path.dirname(__file__)
    with open(os.path.join(script_dir, "config/config.json")) as config_file:
        automated_controls=json.load(config_file)
    region=os.environ['AWS_REGION']
    if region in automated_controls["Controls"]:
        return finding["GeneratorId"] in automated_controls["Controls"][region]
    else:
        return finding["GeneratorId"] in automated_controls["Controls"]["default"]

def lambda_handler(event, context):  # Main function
    utils.validate_environments(
        ["JIRA_API_TOKEN", "AWS_REGION"])

    account_id=event["account"]
    region=os.environ['AWS_REGION']
    os.environ.get("JIRA_CREDENTIALS")
    project_key=os.environ['JIRA_PROJECT_KEY']
    issuetype_name=os.environ['JIRA_ISSUETYPE']
    jira_instance = os.environ['JIRA_INSTANCE']
    jira_credentials = os.environ.get("JIRA_API_TOKEN")

    for finding in event["detail"]["findings"]:
        account, description, severity, title, finding_id, product_arn, resources, status, recordstate=finding_parser(
            finding)
        try:
            if event["detail-type"] == "Security Hub Findings - Custom Action" and event["detail"]["actionName"] == "CreateJiraIssue":
                if status != "NEW":
                    raise UserWarning(
                        "Finding workflow is not NEW: %s" % finding_id)
                if recordstate != "ACTIVE":
                    raise UserWarning("Finding is not ACTIVE: %s" % finding_id)
                jira_client=utils.get_jira_client(secretsmanager,jira_instance,jira_credentials)
                jira_issue=utils.get_jira_finding(
                    jira_client, finding_id, project_key, issuetype_name)
                if not jira_issue:
                    logger.info(
                        "Creating ticket manually for {0}".format(finding_id))
                    create_jira(jira_client, project_key, issuetype_name, product_arn, account,
                                region, description, resources, severity, title, finding_id)
                else:
                    logger.info("Finding {0} already reported in ticket {1}".format(
                        finding_id, jira_issue))
            elif event["detail-type"] == "Security Hub Findings - Imported":
                if recordstate == "ARCHIVED" and status == "NOTIFIED":
                    # Move to resolved
                    jira_client=utils.get_jira_client(secretsmanager,jira_instance,jira_credentials)
                    jira_issue=utils.get_jira_finding(
                        jira_client, finding_id, project_key, issuetype_name)

                    if(jira_issue):
                        utils.close_jira_issue(jira_client, jira_issue)
                        utils.update_securityhub(securityhub, finding_id, product_arn, "RESOLVED",
                                                'Closed JIRA Ticket {0}'.format(jira_issue))
                elif recordstate == "ACTIVE" and status == "RESOLVED":
                    # Move to resolved
                    jira_client=utils.get_jira_client(secretsmanager,jira_instance,jira_credentials)
                    jira_issue=utils.get_jira_finding(
                        jira_client, finding_id, project_key, issuetype_name)

                    if(jira_issue) and utils.is_closed(jira_client, jira_issue):
                        # Reopen closed ticket as it was re-detected
                        utils.reopen_jira_issue(jira_client, jira_issue)
                        utils.update_securityhub(securityhub, finding_id, product_arn, "NOTIFIED",
                                                'Reopening JIRA Ticket {0}'.format(jira_issue))
                elif recordstate == "ACTIVE" and status == "NEW" and is_automated_check(finding):
                    # Check if in automatically list of findings to create automatically
                    jira_client=utils.get_jira_client(secretsmanager,jira_instance,jira_credentials)
                    jira_issue=utils.get_jira_finding(
                        jira_client, finding_id, project_key, issuetype_name)

                    if not jira_issue:
                        logger.info(
                            "Creating ticket automatically for {0}".format(finding_id))
                        create_jira(jira_client, project_key, issuetype_name, product_arn, account,
                                    region, description, resources, severity, title, finding_id)

                else:
                    logger.info(
                        "Not performing any action for {}".format(finding_id))
            else:
                logger.info("Unknown custom action {} {}".format(
                    event["detail-type"], event["detail"]["actionName"]))
        except UserWarning as e:
            logger.error(e)


if __name__ == "__main__":
    if not len(sys.argv) - 1 > 0:
        print("Usage: python security_hub_integration.py event.template")
    template=sys.argv[1]
    with open(template, "r") as event_file:
        security_hub_event=json.load(event_file)
        local_time=datetime.now(timezone.utc).astimezone().isoformat()
        for securityhub_finding in security_hub_event["detail"]["findings"]:
            securityhub_finding["UpdatedAt"]=local_time
        lambda_handler(security_hub_event, None)

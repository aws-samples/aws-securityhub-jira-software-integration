# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import sys
import os
import boto3
from jira import JIRA
import utils

sys.path.append('lib')

logger = logging.getLogger('')
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

securityhub = boto3.client('securityhub')
secretsmanager = boto3.client('secretsmanager')


def lambda_handler(event, context):
    utils.validate_environments(
        ["JIRA_API_TOKEN", "AWS_REGION"])
    
    region = os.environ['AWS_REGION']
    jira_instance = os.environ['JIRA_INSTANCE']
    jira_credentials = os.environ.get("JIRA_API_TOKEN")
    project_key = os.environ['JIRA_PROJECT_KEY']
    issuetype_name = os.environ['JIRA_ISSUETYPE']

    jira_client = utils.get_jira_client(secretsmanager,jira_instance,jira_credentials)
    latest = utils.get_jira_latest_updated_findings(
        jira_client, project_key, issuetype_name)
    for ticket in latest:
        try:
            logger.info("Checking {0}".format(ticket))
            finding_id = utils.get_finding_id_from(ticket)
            if finding_id:
                results = securityhub.get_findings(Filters={"Id": [{
                    'Value': finding_id,
                    'Comparison': 'EQUALS'
                }]}
                )
                if len(results["Findings"]) > 0:
                    finding = results["Findings"][0]
                    finding_status = finding["Workflow"]["Status"]
                    product_arn = finding["ProductArn"]
                    record_state = finding["RecordState"]

                    if utils.is_suppressed(jira_client, ticket) and finding_status != "SUPPRESSED":
                        # If accepted or false positive in JIRA, mark as suppressed in Security Hub
                        logger.info("Suppress {0} based on {1}".format(
                            finding_id, ticket))
                        utils.update_securityhub(
                            securityhub, finding_id, product_arn, "SUPPRESSED", 'JIRA Ticket: {0}'.format(ticket))

                    if utils.is_closed(jira_client, ticket) and finding_status != "RESOLVED":
                        # If closed in JIRA, mark as Resolved in Security Hub
                        logger.info("Marking as resolved {0} based on {1}".format(
                            finding_id, ticket))
                        utils.update_securityhub(
                            securityhub, finding_id, product_arn, "RESOLVED", 'JIRA Ticket was resolved')

                    if not utils.is_closed(jira_client, ticket) and not utils.is_suppressed(jira_client, ticket):
                        if record_state != "ARCHIVED" and finding_status != "NOTIFIED":
                            # If Security Hub finding is still ACTIVE but supressed and JIRA is not closed, move back to NOTIFIED
                            logger.info("Reopen {0} based on {1}".format(
                                finding_id, ticket))
                            utils.update_securityhub(
                                securityhub, finding_id, product_arn, "NOTIFIED", 'JIRA Ticket: {0}'.format(ticket))

                        if record_state == "ARCHIVED" and finding_status != "RESOLVED":
                            # If Security Hub finding is still ARCHIVED, then it was resolved, close JIRA issue and resolve Security Hub
                            logger.info("Closing {1} based on {0} archived status".format(
                                finding_id, ticket))
                            utils.close_jira_issue(jira_client, ticket)
                            utils.update_securityhub(
                                securityhub, finding_id, product_arn, "RESOLVED", 'Closed JIRA Ticket {0}'.format(ticket))
                else:
                    raise UserWarning(
                        "aws-sec label found for {0} but couldn't find the related Security Hub finding".format(ticket))
        except UserWarning as e:
            logger.error(e)


if __name__ == "__main__":
    lambda_handler(None, None)

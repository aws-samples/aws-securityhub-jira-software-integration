# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import json
import security_hub_integration
import warnings
import utils
import logging

class TestSecurityHubtoJiraIntegration(unittest.TestCase):

    def setUp(self):
        # https://github.com/boto/boto3/issues/454
        warnings.filterwarnings(
            "ignore", category=ResourceWarning, message="unclosed.*<ssl.SSLSocket.*>")

    def load_test(self, template):
        with open(template, "r") as event_file:
            event = json.load(event_file)
            local_time = datetime.now(timezone.utc).astimezone().isoformat()
            for finding in event["detail"]["findings"]:
                finding["UpdatedAt"] = local_time
        return event

    @patch('security_hub_integration.utils.ticket_creator')
    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.update_jira_assignee')
    def test_custom_action_new_finding(self, ticket_creator, update_securityhub, update_jira_assignee):
        event = self.load_test('test/custom_new.template')
        security_hub_integration.lambda_handler(event, None)
        ticket_creator.assert_called_once()
        update_securityhub.assert_called_once()
        update_jira_assignee.assert_called_once()

    @patch('security_hub_integration.utils.ticket_creator')
    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.update_jira_assignee')
    def test_custom_action_existing_ticket(self, ticket_creator, update_securityhub, update_jira_assignee):
        event = self.load_test('test/custom_new_existing.template')
        security_hub_integration.lambda_handler(event, None)
        ticket_creator.assert_not_called()
        update_securityhub.assert_not_called()
        update_jira_assignee.assert_not_called()

    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.close_jira_issue')
    def test_imported_archived_new_finding(self, update_securityhub, close_jira_issue):
        event = self.load_test('test/imported_archived_new.template')
        security_hub_integration.lambda_handler(event, None)
        update_securityhub.assert_not_called()
        close_jira_issue.assert_not_called()

    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.close_jira_issue')
    def test_imported_archived_existing_ticket(self, update_securityhub, close_jira_issue):
        event = self.load_test(
            'test/imported_archived_existing.template')
        security_hub_integration.lambda_handler(event, None)
        update_securityhub.assert_called()
        close_jira_issue.assert_called()

    @patch('security_hub_integration.utils.ticket_creator')
    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.update_jira_assignee')
    def test_imported_new_automated_finding(self, ticket_creator, update_securityhub, update_jira_assignee):
        event = self.load_test('test/imported_new_automated.template')
        security_hub_integration.lambda_handler(event, None)
        ticket_creator.assert_called()
        update_securityhub.assert_called()
        update_jira_assignee.assert_called()

    @patch('security_hub_integration.utils.ticket_creator')
    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.update_jira_assignee')
    def test_imported_new_automated_standard_finding(self, ticket_creator, update_securityhub, update_jira_assignee):
        event = self.load_test(
            'test/imported_new_automated_standard_check.template')
        security_hub_integration.lambda_handler(event, None)
        ticket_creator.assert_called()
        update_securityhub.assert_called()
        update_jira_assignee.assert_called()

    @patch('security_hub_integration.utils.ticket_creator')
    @patch('security_hub_integration.utils.update_securityhub')
    @patch('security_hub_integration.utils.update_jira_assignee')
    def test_imported_new_not_automated_finding(self, ticket_creator, update_securityhub, update_jira_assignee):
        event = self.load_test('test/imported_new_notautomated.template')
        security_hub_integration.lambda_handler(event, None)
        ticket_creator.assert_not_called()
        update_securityhub.assert_not_called()
        update_jira_assignee.assert_not_called()


if __name__ == '__main__':
    unittest.main()

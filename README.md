# Security Hub JIRA Integration

## Summary

This solution supports a bidirectional integration between Security Hub and JIRA. Issues can be either created automatically or manually by using custom actions.

## Features

The solution allows you to:

- Select which specific AWS Security Hub controls to automatically create in JIRA using their GeneratorId field (see Security Hub ASFF format).

- Manually escalate tickets in JIRA through Security Hub console using Security Hub Custom Actions.

- Assign tickets per AWS accounts using AWS Organization account "SecurityContactID" tags. A "default assignee" is used if no tag exists.

- Automatically suppress AWS Security Hub findings that are marked as false positive or accepted risk in JIRA.

- Automatically close JIRA tickets when its related finding is archived in Security Hub.

- Reopen tickets when AWS Security findings reoccur.

## Description

The solution uses a custom JIRA workflow to reflect the risk management of each finding. Workflow is inspired by [DinisCruz SecDevOps risk workflow](https://www.slideshare.net/DinisCruz/secdevops-risk-workflow-v06).

![Workflow](asset/workflow.png)

## Architecture

![Architecture](asset/architecture.png)

## How it works

1. A new finding AWS Foundational Security Best Practices standard is imported to Security Hub

2. A Cloudwatch events trigger a Lambda function to identify whether to escalate the finding

3. Lambda determines whether findings is escalated based on its configuration file and the finding's GeneratorId field. If so, it assumes a role to AWS Organization management account to obtain the correct JIRA ticket assignee ID using the from the "SecurityContactID" account tag. If not found, uses the `DefaultAssignee`.

The Lambda creates the ticket in JIRA using credentials stored in Secrets Manager. It then updates the Security Hub finding to NOTIFIED and adds a note with a link to the related JIRA ticket. 

Scenario 1: Developer addresses the issue

4. The developer assignee addresses the underlying security finding and moves the ticket to "TEST FIX".
5. When Security Hub finding is updated as ARCHIVED, the same Lambda from step 3 will automatically close the JIRA ticket.   

*Scenario 2: Developer decides to accept the risk*

4. The developer assignee decides to accept the risk and moves the ticket to "AWAITING RISK ACCEPTANCE". A security engineer reviews the request and finds business justification appropriate and moves the finding to "ACCEPTED RISK".

5. A daily event is triggered causing the refresh Lambda to identify closed JIRA tickets and update their related Security Hub findings as SUPPRESSED.

## How to deploy?

### Prerequisites

* JIRA Server instance.
*Note*: JIRA Cloud is supported but JIRA workflow XML cannot be imported and needs to be recreated.
* JIRA Administrator permissions. 
* JIRA Username Personal Access Token (PAT) for JIRA Enterprise ([how to generate PAT tokens](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html)) or JIRA API Token for JIRA Cloud ([how to generate API tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)). 
* Cross account AWSOrganizationsReadOnlyAccess permissions to Organization management account. Required to retrieve Security Contact account tag. Alternatively, You can use default assignee to deploy without this permissions  
* Access to AWS Audit account to escalate findings across Organization. Alternatively you can use any account to escalate only Security findings from that account.

### Step 1: Configure

1. As JIRA Administrator, import `issue-workflow.xml` file to your JIRA Server instance. Check out [related documentation](https://confluence.atlassian.com/adminjiraserver/using-xml-to-create-a-workflow-938847525.html). 
2. Create a new issue type (or use an already existing type such as Bug) for the project and assign to the workflow scheme created above ([JIRA documentation](https://support.atlassian.com/jira-cloud-administration/docs/manage-issue-workflows/))
4. Modify `conf/params_prod.sh` with the following values:
    * ORG_ACCOUNT_ID: Account ID for Organization Management account. The solution assumes the role below to read account tags to assign ticket to the specific AWS account security contact.
    * ORG_ROLE: OrganizationsReadOnlyAccess. Name of the role assumed to AWS Organization management account.
    * EXTERNAL_ID: Optional parameters if using External Id to assume the role above. 
    * JIRA_DEFAULT_ASSIGNEE: This is the JIRA ID for default assignee for all Security Issues. This default assigned is used in case account is not tagged properly or role cannot be assumed.
    * JIRA_INSTANCE: HTTPS address for JIRA server. For example, https://team-1234567890123.atlassian.net/
    * JIRA_PROJECT_KEY: Name of the JIRA Project Key used to create tickets. This project needs to already exist in JIRA. Examples: "SEC", "TEST", etc. 
    * ISSUE_TYPE: JIRA Issuetype name: Examples would be "Bug", "Security Issue"
    * REGIONS:  List of regions where to deploy. Example: ("eu-west-1")

### Step 2: Create custom action

1. Use the aws security hub create-action-target CLI command on each region deployed to create a "CreateTicket" custom action:
`aws securityhub create-action-target --name "CreateJiraIssue" --description "Create ticket in JIRA" --id "CreateJiraIssue" --region $AWS_REGION`

### Step 3: Deploy

1. Set AWS enviroment variables for credential, like AWS_SECRET_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION
2. Execute `./deploy.sh [prod]"
3. Upload your JIRA Credentials to `JIRA-Token` via AWS Secrets Manager console:
    * For JIRA Enterprise: Add `auth` as `token_auth` and for `token` add Personal Access Token (PAT)
    * For JIRA Cloud: Add `auth` as `basic_auth` and add both `email` and `token` fields of your integration user API token.

### Step 4: Including new automated controls

You can specify type of findings which are automated using `GeneratorId` field. You can choose different findings to automate per region. For example, selecting that `eu-west-1` region is the only region creating IAM related tickets. To add controls, add its `GeneratorId` under its `config.json`.    

### Step 5: Test solution

1. Open the [AWS Security Hub console](https://console.aws.amazon.com/securityhub/), under navigation panel, choose Findings. In the finding's list, select the checkbox for findings to escalate.
2. under Actions, click on "CreateJiraIssue" actions.

## Troubleshooting

### Access Denied for s3:SetBucketEncryption in LptBucket

If you're using Control Tower Audit account, please make sure to update your Landing Zone to the latest version. See how to update [here](https://docs.aws.amazon.com/controltower/latest/userguide/configuration-updates.html).

You can remove choose to either disable encryption and lifecycle policies from `lpt-basic.yml` or disable the following elective guardrails: 
- Disallow Changes to Encryption Configuration for Amazon S3 Buckets.
- Disallow Changes to Lifecycle Configuration for Amazon S3 Buckets

## Deleting resources

1. Search for `artifact-securityhub` and select `Empty` and confirm operation. 
2. Access [AWS CloudFormation](https://console.aws.amazon.com/cloudformation/home) console. For both stacks,  `securityhub-jira-prod-solution` and `securityhub-jira-prod-artifact`, click on `Delete`.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.


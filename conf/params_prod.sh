# Stack parameter
export ORG_ACCOUNT_ID='' # ID for Organization Management account 
export ORG_ROLE=OrganizationsReadOnlyAccess
export AWS_REGION=eu-west-1
export EXTERNAL_ID='' #Optional 
export JIRA_DEFAULT_ASSIGNEE='' #ID for default assignee for all Security Issues
export JIRA_INSTANCE="" #HTTPS address for JIRA server
export JIRA_PROJECT_KEY="" # JIRA Project Key
export ISSUE_TYPE="" #JIRA Issuetype name: Example, "Bug", "Security Issue"
export REGIONS=("eu-west-1") # List of regions deployed

PARAMETERS=(
  "OrganizationManagementAccountId=$ORG_ACCOUNT_ID"
  "JIRADefaultAssignee=$JIRA_DEFAULT_ASSIGNEE"
  "OrganizationAccessExternalId=$EXTERNAL_ID"
  "AutomatedChecks=$AUTOMATED_CHECKS"
  "JIRAInstance=$JIRA_INSTANCE"
  "JIRAIssueType"="$ISSUE_TYPE"
  "JIRAProjectKey"="$JIRA_PROJECT_KEY"
)




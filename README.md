
# aws-securityhub-jira-software-integration

This solution supports a bidirectional integration between AWS Security Hub and Jira. Using this solution, you can automatically and manually create and update JIRA tickets from Security Hub findings. Security teams can use this integration to notify developer teams of severe security findings that require action. 

The solution allows you to:

- Select which Security Hub controls automatically create or update tickets in Jira.
- In the Security Hub console, use Security Hub custom actions to manually escalate tickets in Jira.
- Automatically assign tickets in Jira based on the AWS account tags defined in AWS Organizations. If this tag is not defined, a default assignee is used.
- Automatically suppress Security Hub findings that are marked as false positive or accepted risk in Jira.
- Automatically close a Jira ticket when its related finding is archived in Security Hub.
- Reopen Jira tickets when Security Hub findings reoccur.

For the architecture diagram, prerequisites, and instructions for using this AWS Prescriptive Guidance pattern, see [Bidirectionally integrate AWS Security Hub with Jira software](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/bidirectionally-integrate-aws-security-hub-with-jira-software.html).

#!/bin/bash
set -eio pipefail    

function print_usage (){
	echo "------------------------------------------------------------------------------"
	echo "	This script deploys the code without pipeline"
	echo "------------------------------------------------------------------------------"
	echo "Usage: ./deploy.sh [env]"
	echo "For example 1: ./deploy.sh prod"
	echo "For example 2: ./deploy.sh local"
	echo 
	echo "environment points to config file to load"
}

# Load the config 
if [ -z $1 ]; then 
	echo "Assuming params already configured"
else 
   	echo "loading params from \"conf/params_${1}.sh\"  with environment variables"	
	. conf/params_${1}.sh
fi

for regx in ${REGIONS[@]}; do

	ENVIRONMENT="$1"
	export AWS_REGION=$regx
	ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
	BASE="securityhub-jira-$1" 

	function ensure_basic {
	$AWS_CFN deploy --stack-name "${BASE}-artifact" --template-file src/template/lpt-basic.yaml --no-fail-on-empty-changeset --parameter-overrides BucketName="artifact-securityhub-jira-$ENVIRONMENT-$AWS_REGION-$ACCOUNT"
	BUCKET=$($AWS_CFN describe-stacks --stack-name "${BASE}-artifact" --query Stacks[].Outputs[*].[OutputKey,OutputValue] --output text | grep LptBucket | awk '{ print $2 }')
	}

	function ensure_environment_variable_is_set {
	test -n "${!1}" || { echo >&2 "Required environment variable '$1' not found. Aborting."; exit 1; }
	}

	ensure_environment_variable_is_set AWS_REGION 

	export AWS_CFN="aws cloudformation --region $AWS_REGION"

	ensure_basic

	# Clean up dist folder
	rm -r dist/* || mkdir -p dist

	# Restore .gitignore
	#echo '*' > dist/.gitignore

	# Copy new versions of Lambda
	cp -r src/* dist/

	# Install JIRA from master (assign_issue GDPR)
	INSTALL_PREREQUISITES=$(cd dist/code && pip3 install -t . jira==3.1.1)

	# ZIP Dependency
	INSTALL_LAMBDA=$(cd dist/code && zip -r9 ../lambda.zip ./)

	# Package cloudformation into S3 artifact
	$AWS_CFN package --template src/template/cloudformation_template.yaml --s3-bucket "$BUCKET" --output-template-file dist/template/deployment-version.yaml 

	# Validate template
	$AWS_CFN validate-template --template-body file://$(pwd)/dist/template/deployment-version.yaml > /dev/null || exit 1

	$AWS_CFN deploy --template-file dist/template/deployment-version.yaml --capabilities CAPABILITY_NAMED_IAM --stack-name "$BASE-solution"  --parameter-overrides "${PARAMETERS[@]}"  

done
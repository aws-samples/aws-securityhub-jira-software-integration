#!/bin/bash
set -eio pipefail    

# Load the config 
if [ -z $1 ]; then 
	echo "Please specify the environment, Example: ./test.sh prod"
	exit 1
else 
   	echo "loading params from \"conf/params_${1}.sh\" environment variables"	
	. conf/params_${1}.sh
fi

. conf/params_${1}.sh
export JIRA_API_TOKEN='mock_token'
export JIRA_ISSUETYPE='mock_issuetype'

python3 -m unittest discover src/code
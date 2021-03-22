#!/bin/sh
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

#######################
### function: clean ###
#######################
cleanApigeeObjects() {

    # force deletion of identityApp developer app
    deleteApp=$(curl --silent -X DELETE -H "Authorization: Bearer $TOKEN" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/developers/jdoe@example.com/apps/identityApp)
    
    # force deletion of app developer 
    deleteDeveloper=$(curl --silent -X DELETE -H "Authorization: Bearer $TOKEN" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/developers/jdoe@example.com)
    
    # force deletion of api product
    deleteProduct=$(curl --silent -X DELETE -H "Authorization: Bearer $TOKEN" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/apiproducts/IdentityFacadePdt)
    
    # force deletion of idpConfig properties file
    deleteProperties=$(curl --silent -X DELETE -H "Authorization: Bearer $TOKEN" -H "application/octet-stream" "https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/environments/"$APIGEE_ENV"/resourcefiles/properties/idpConfig")
    
}


#################################
### function: set_idp_env_var ###
#################################
set_idp_env_var() {

    # discovery document of an OIDC compliant IdP
    idp_discovery_document=https://"$RUNTIME_HOST_ALIAS"/v1/openid-connect/.well-known/openid-configuration

    # retrieve configuration data from a discovery document
    response=$(curl --silent -k1 -fsSL -X GET -H "Accept:application/json" "$idp_discovery_document")
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"
        
        exit 1
    fi

    # extract data used to feed the kvm
    issuer=$( printf '%s' "$response" | jq .issuer )
    authorization_endpoint=$( printf '%s' "$response" | jq .authorization_endpoint )
    token_endpoint=$( printf '%s' "$response" | jq .token_endpoint )
    jwks_uri=$( printf '%s' "$response" | jq .jwks_uri )
    userinfo_endpoint=$( printf '%s' "$response" | jq .userinfo_endpoint )

    # set env variables for kvm (idpConfig)
    TEST_IDP_ISSUER=$(printf '%s' "$issuer" | awk -F\" '{print $2}' | awk -F\" '{print $1}')
    export TEST_IDP_ISSUER
    
    TEST_IDP_APIGEE_REDIRECT_URI="https://"$RUNTIME_HOST_ALIAS"/v1/oauth20/callback"
    export TEST_IDP_APIGEE_REDIRECT_URI
    
    TEST_IDP_AZ_HOSTNAME=$(printf '%s' "$authorization_endpoint" | awk -F\"https:// '{print $2}' | awk -F\" '{print $1}' | awk -F/ '{print $1}')
    export TEST_IDP_AZ_HOSTNAME
    
    TEST_IDP_TOKEN_HOSTNAME=$(printf '%s' "$token_endpoint" | awk -F\"https:// '{print $2}' | awk -F\" '{print $1}' | awk -F/ '{print $1}')
    export TEST_IDP_TOKEN_HOSTNAME
    
    TEST_IDP_JWKS_HOSTNAME=$(printf '%s' "$jwks_uri" | awk -F\"https:// '{print $2}' | awk -F\" '{print $1}' | awk -F/ '{print $1}')
    export TEST_IDP_JWKS_HOSTNAME
    
    TEST_IDP_USERINFO_HOSTNAME=$(printf '%s' "$userinfo_endpoint" | awk -F\"https://  '{print $2}' | awk -F\" '{print $1}' | awk -F/ '{print $1}')
    export TEST_IDP_USERINFO_HOSTNAME
    
    TEST_IDP_TOKEN_URI=$(printf '%s' "$token_endpoint" | awk -F "$TEST_IDP_TOKEN_HOSTNAME"'/' '{print $2}' | awk -F\" '{print $1}')
    export TEST_IDP_TOKEN_URI
    
    TEST_IDP_AZ_URI=$(printf '%s' "$authorization_endpoint" | awk -F "$TEST_IDP_AZ_HOSTNAME"'/' '{print $2}' | awk -F\" '{print $1}')
    export TEST_IDP_AZ_URI
    
    TEST_IDP_JWKS_URI=$(printf '%s' "$jwks_uri" | awk -F "$TEST_IDP_JWKS_HOSTNAME"'/' '{print $2}' | awk -F\" '{print $1}')
    export TEST_IDP_JWKS_URI
    
    TEST_IDP_USERINFO_URI=$(printf '%s' "$userinfo_endpoint" | awk -F "$TEST_IDP_USERINFO_HOSTNAME"'/' '{print $2}' | awk -F\" '{print $1}') 
    export TEST_IDP_USERINFO_URI

    TEST_IDP_APIGEE_CLIENT_ID="dummy-client_id-apigee123"
    export TEST_IDP_APIGEE_CLIENT_ID

    TEST_IDP_APIGEE_CLIENT_SECRET="dummy-client_secret_apigee456"
    export TEST_IDP_APIGEE_CLIENT_SECRET
}

####################################################
### function: generate_post_data_app_credentials ###
####################################################
generate_properties()
{
  cat <<EOF
idp-issuer=$TEST_IDP_ISSUER
idp-apigee-redirect-uri=$TEST_IDP_APIGEE_REDIRECT_URI
idp-az-hostname=$TEST_IDP_AZ_HOSTNAME
idp-token-hostname=$TEST_IDP_TOKEN_HOSTNAME
idp-jwks-hostname=$TEST_IDP_JWKS_HOSTNAME
idp-userinfo-hostname=$TEST_IDP_USERINFO_HOSTNAME
idp-token-uri=$TEST_IDP_TOKEN_URI
idp-az-uri=$TEST_IDP_AZ_URI
idp-jwks-uri=$TEST_IDP_JWKS_URI
idp-userinfo-uri=$TEST_IDP_USERINFO_URI
idp-apigee-client-id=dummy-client_id-123a
idp-apigee-client-secret=dummy-client_secret-456b
EOF
}

##########################################
### function: set_idpconfig_properties ###
##########################################
set_idpconfig_properties() {
    # use apigee api
    response=$(curl --silent -X POST -H "Content-Type: application/octet-stream" --data "$(generate_properties)" -H "Authorization: Bearer $TOKEN" -H "application/octet-stream" "https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/environments/"$APIGEE_ENV"/resourcefiles?type=properties&name=idpConfig")
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"
        
        exit 1
    fi
}

####################################################
### function: generate_post_data_app_credentials ###
####################################################
generate_post_data_app_credentials()
{
  cat <<EOF
{
  "consumerKey": "$TEST_APP_CONSUMER_KEY",
  "consumerSecret": "xsecret"
}
EOF
}

#########################################################
### function: generate_post_data_app_identity_product ###
#########################################################
generate_post_data_app_identity_product()
{
  cat <<EOF
{ 
    "apiProducts": ["IdentityFacadePdt"] 
}
EOF
}

########################################
### function: set_devapp_credentials ###
########################################
set_devapp_credentials() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_app_credentials)" -H "Authorization: Bearer $TOKEN" -H "Content-Type:application/json" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/developers/jdoe@example.com/apps/identityApp/keys/create)
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"
        
        exit 1
    fi
}

####################################
### function: set_devapp_product ###
####################################
set_devapp_product() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_app_identity_product)" -H "Authorization: Bearer $TOKEN" -H "Content-Type:application/json" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/developers/jdoe@example.com/apps/identityApp/keys/"$TEST_APP_CONSUMER_KEY")
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"

        exit 1
    fi
}

################################
### function: set_idp_env_var ###
#################################
set_functional_test_env_var() {

    # use timestamp (parameter) to create a unique value
    TEST_APP_CONSUMER_KEY="xkey-$1"
    export TEST_APP_CONSUMER_KEY
}

##############################################
### function: generate_post_data_developer ###
##############################################
generate_post_data_developer()
{
  cat <<EOF
{
  "email": "jdoe@example.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "userName": "jdoe"
}
EOF
}

###############################
### function: set_developer ###
###############################
set_developer() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_developer)" -H "Authorization: Bearer $TOKEN" -H "Content-Type:application/json" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/developers)
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"

        exit 1
    fi
}

###############################################
### function: generate_post_data_apiproduct ###
###############################################
generate_post_data_apiproduct()
{
  cat <<EOF
{
    "name": "IdentityFacadePdt",
    "apiResources": [],
    "approvalType": "auto",
    "attributes": [
        {
            "name": "access",
            "value": "public"
        }
    ],
    "description": "",
    "displayName": "Identity Facade",
    "environments": [
        "test"
    ],
    "proxies": [
        "identity-facade-v1"
    ]
}
EOF
}

################################
### function: set_apiproduct ###
################################
set_apiproduct() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_apiproduct)" -H "Authorization: Bearer $TOKEN" -H "Content-Type:application/json" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/apiproducts)
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"

        exit 1
    fi
}

#################################################
### function: generate_post_data_developerapp ###
#################################################
generate_post_data_developerapp()
{
  cat <<EOF
{
  "name": "identityApp",
  "apiProducts": [
    "IdentityFacadePdt"
  ],
  "developerId": "jdoe@example.com",
  "callbackUrl": "https://httpbin.org/get"
}
EOF
}

##################################
### function: set_developerapp ###
##################################
set_developerapp() {
    # retrieve configuration data from a keycloak endpoint
    response=$(curl --silent -X POST --data "$(generate_post_data_developerapp)" -H "Authorization: Bearer $TOKEN" -H "Content-Type:application/json" https://apigee.googleapis.com/v1/organizations/"$APIGEE_ORG"/developers/jdoe@example.com/apps)
    if [ "$( printf '%s' "$response" | grep -c error )" -ne 0  ]; then
        echo "$response"

        exit 1
    fi
}


# generate a token a gcloud token
TOKEN=$(gcloud auth print-access-token)

# deploy the OIDC mock identity provider...
#cd ../oidc-mock
#mvn install -P"$APIGEE_ENV" -Dbearer="$TOKEN"
#npm install
#npm test

#...then deploy the identity-facade proxy
#cd ../identity-facade

# force deletion of properties file, app, developer app and api product
cleanApigeeObjects

# generate a timestamp to make some values unique
timestamp=$(date '+%s')

# set env variables for google oidc
set_idp_env_var

# set idpConfig properties file
set_idpconfig_properties

set_functional_test_env_var "$timestamp"

# deploy Apigee artifacts: proxy, developer, app, product cache, kvm and proxy
mvn install -P"$APIGEE_ENV" -Dbearer="$TOKEN"

# create in order: 1. developer, 2. api product, 3. app
#.1
set_developer

#.2
set_apiproduct

#.3
set_developerapp

# set developer app credentials for functional test
set_devapp_credentials

# set developer app product for functional test
set_devapp_product

# execute integration tests
npm install
npm run test

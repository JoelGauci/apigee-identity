/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var idpIssuer = context.getVariable("propertyset.idpConfig.idp-issuer");
var idpApigeeRedirectUri = context.getVariable("propertyset.idpConfig.idp-apigee-redirect-uri");
var idpAzHostname = context.getVariable("propertyset.idpConfig.idp-az-hostname");
var idpTokenHostname = context.getVariable("propertyset.idpConfig.idp-token-hostname");
var idpJwksHostname = context.getVariable("propertyset.idpConfig.idp-jwks-hostname");
var idpUserinfoHostname = context.getVariable("propertyset.idpConfig.idp-userinfo-hostname");
var idpTokenUri = context.getVariable("propertyset.idpConfig.idp-token-uri");
var idpAzUri = context.getVariable("propertyset.idpConfig.idp-az-uri");
var idpJwksUri = context.getVariable("propertyset.idpConfig.idp-jwks-uri");
var idpUserinfoUri = context.getVariable("propertyset.idpConfig.idp-userinfo-uri");
var idpApigeeClientId = context.getVariable("propertyset.idpConfig.idp-apigee-client-id");
var idpApigeeClientSecret = context.getVariable("propertyset.idpConfig.idp-apigee-client-secret");

context.setVariable('flow.idp.issuer',idpIssuer);
context.setVariable('flow.idp.apigee.redirect_uri',idpApigeeRedirectUri);
context.setVariable('flow.idp.az.hostname',idpAzHostname);
context.setVariable('flow.idp.token.hostname',idpTokenHostname);
context.setVariable('flow.idp.jwks.hostname',idpJwksHostname);
context.setVariable('flow.idp.userinfo.hostname',idpUserinfoHostname);
context.setVariable('flow.idp.token.uri',idpTokenUri);
context.setVariable('flow.idp.az.uri',idpAzUri);
context.setVariable('flow.idp.jwks.uri',idpJwksUri);
context.setVariable('flow.idp.userinfo.uri',idpUserinfoUri);
context.setVariable('flow.idp.apigee.client_id',idpApigeeClientId);
context.setVariable('flow.idp.apigee.client_secret',idpApigeeClientSecret);

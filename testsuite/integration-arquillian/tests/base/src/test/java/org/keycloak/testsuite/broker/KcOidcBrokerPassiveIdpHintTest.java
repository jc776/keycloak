/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.broker;

import java.util.Collections;
import java.util.List;

import javax.ws.rs.core.Response;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.util.ClientManager;
import org.keycloak.testsuite.util.OAuthClient;

import static org.keycloak.testsuite.admin.ApiUtil.createUserWithAdminClient;
import static org.keycloak.testsuite.admin.ApiUtil.resetUserPassword;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author JCoady
 */
public class KcOidcBrokerPassiveIdpHintTest extends AbstractBaseBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerConfiguration.INSTANCE;
    }

    @Before
    public void createUser() {
        log.debug("creating user for realm " + bc.providerRealmName());

        UserRepresentation user = new UserRepresentation();
        user.setUsername(bc.getUserLogin());
        user.setEmail(bc.getUserEmail());
        user.setEmailVerified(true);
        user.setEnabled(true);

        RealmResource realmResource = adminClient.realm(bc.providerRealmName());
        String userId = createUserWithAdminClient(realmResource, user);

        resetUserPassword(realmResource.users().get(userId), bc.getUserPassword(), false);
    }

    // TODO: Possibly move to parent superclass
    @Before
    public void addIdentityProviderToProviderRealm() {
        log.debug("adding identity provider to realm " + bc.consumerRealmName());

        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        Response resp = realm.identityProviders().create(bc.setUpIdentityProvider(suiteContext));
        resp.close();
    }

    @Before
    public void addClients() {
        List<ClientRepresentation> clients = bc.createProviderClients(suiteContext);
        if (clients != null) {
            RealmResource providerRealm = adminClient.realm(bc.providerRealmName());
            for (ClientRepresentation client : clients) {
                log.debug("adding client " + client.getClientId() + " to realm " + bc.providerRealmName());

                Response resp = providerRealm.clients().create(client);
                resp.close();
            }
        }

        clients = bc.createConsumerClients(suiteContext);
        if (clients != null) {
            RealmResource consumerRealm = adminClient.realm(bc.consumerRealmName());
            for (ClientRepresentation client : clients) {
                log.debug("adding client " + client.getClientId() + " to realm " + bc.consumerRealmName());

                Response resp = consumerRealm.clients().create(client);
                resp.close();
            }
        }
    }
    
//    @Test
//    public void testPassiveIdpHintSuccess() throws Exception {
//    	// log in for the first time to set up provider
//    	logInAsUserInIDPForFirstTime();
//        assertLoggedInAccountManagement();
//        logoutFromRealm(bc.consumerRealmName());
//    	
//        // log in to provider without going through consumer
//        logInAsUserToProvider();
//        assertLoggedInAccountManagement();
//    	
//        // - account
//        // - some client secret (do I care?)
//        // - /auth/realms/master/account/*
//        // - /auth/realms/master/account
//        ClientManager.realm(adminClient.realm("master")).clientId("account").addRedirectUris("https://www.google.com/");
//        oauth.realm(bc.consumerRealmName());
//        oauth.clientId("account");
//        oauth.redirectUri("https://www.google.com/");
//        final String pp = oauth.getLoginFormUrl() + "&prompt=none" + "&kc_idp_hint=" + BrokerTestConstants.IDP_OIDC_ALIAS;
//        // http://localhost:8180/auth/realms/test/protocol/openid-connect/auth?response_type=code&client_id=account&redirect_uri=https%3A%2F%2Fwww.google.com%2F&state=d912a949-9a8e-44ce-9925-271f384f9e31&scope=openid&prompt=none&kc_idp_hint=kc-oidc-idp
//        log.debug(pp);
//        driver.navigate().to(pp);
//        
//        // http://localhost:8180/auth/realms/test/protocol/openid-connect/auth?response_type=code&client_id=account&redirect_uri=https%3A%2F%2Fwww.google.com%2F&state=d912a949-9a8e-44ce-9925-271f384f9e31&scope=openid&prompt=none&kc_idp_hint=kc-oidc-idp
//        // expected 'google' - maybe the redirect URI didn't work. Could add a custom client.
//        log.debug(driver.getCurrentUrl());
//
//        // current behaviour: "Login required", since you're not in on consumer.
//        // wanted behaviour: log in to consumer immediately
//        OAuthClient.AuthorizationEndpointResponse resp = new OAuthClient.AuthorizationEndpointResponse(oauth);
//        Assert.assertNull(resp.getCode());
//        Assert.assertEquals(OAuthErrorException.LOGIN_REQUIRED, resp.getError());
//        
//        // http://localhost:8180/auth/realms/test/protocol/openid-connect/auth?response_type=code&client_id=account
//        // &redirect_uri=http%3A%2F%2Flocalhost%3A8180%2Fauth%2Frealms%2Fconsumer%2Faccount&state=ef092183-39c8-4392-8db0-eab2c3ddf804&scope=openid&prompt=none&kc_idp_hint=kc-oidc-idp
//
//        
//        Assert.fail(pp);
//    }
    
    @Test
    public void testIdpHintOnly() throws Exception {
    	// log in for the first time to set up provider
    	logInAsUserInIDPForFirstTime();
        assertLoggedInAccountManagement();
        logoutFromRealm(bc.consumerRealmName());
        
    	
        // log in to provider without going through consumer
        log.debug("Log in to provider - ");
        logInAsUserToProvider();
        assertLoggedInAccountManagement();
    	
        log.debug("Now go to consumer - ");
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()) + "?kc_idp_hint=" + BrokerTestConstants.IDP_OIDC_ALIAS);
        // fails.
        assertLoggedInAccountManagement();
    }
    
//    @Test
//    public void testPassiveIdpHintB() throws Exception {
//    	// log in for the first time to set up provider
//    	logInAsUserInIDPForFirstTime();
//        assertLoggedInAccountManagement();
//        
//        // just try prompt=none
//        oauth.clientId("account");
//        oauth.redirectUri(getAccountUrl(bc.consumerRealmName()));
//        final String pp = oauth.getLoginFormUrl() + "&prompt=none" + "&kc_idp_hint=" + BrokerTestConstants.IDP_OIDC_ALIAS;
//        
//        log.debug(pp);
//        driver.navigate().to(pp);
//        
//        // http://localhost:8180/auth/realms/test/protocol/openid-connect/auth?response_type=code&client_id=account&redirect_uri=https%3A%2F%2Fwww.google.com%2F&state=d912a949-9a8e-44ce-9925-271f384f9e31&scope=openid&prompt=none&kc_idp_hint=kc-oidc-idp
//        // expected 'google' - maybe the redirect URI didn't work. Could add a custom client.
//        log.debug(driver.getCurrentUrl());
//
//        // current behaviour: "Login required", since you're not in on consumer.
//        // wanted behaviour: log in to consumer immediately
//        OAuthClient.AuthorizationEndpointResponse resp = new OAuthClient.AuthorizationEndpointResponse(oauth);
//        Assert.assertNull(resp.getCode());
//        Assert.assertEquals(OAuthErrorException.LOGIN_REQUIRED, resp.getError());
//    }
    
    protected void logInAsUserToProvider() {
        driver.navigate().to(getAccountUrl(bc.providerRealmName()));

        waitForPage(driver, "log in to", true);

        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));

        log.debug("Logging in");
        accountLoginPage.login(bc.getUserLogin(), bc.getUserPassword());
    }

// reconfigure
//    private RealmResource providerRealm() {
//        return adminClient.realm(bc.providerRealmName());
//    }
//
//    private IdentityProviderRepresentation getIdentityProvider() {
//        return consumerRealm().identityProviders().get(BrokerTestConstants.IDP_OIDC_ALIAS).toRepresentation();
//    }
//
//    private void updateIdentityProvider(IdentityProviderRepresentation rep) {
//        consumerRealm().identityProviders().get(BrokerTestConstants.IDP_OIDC_ALIAS).update(rep);
//    }
//
//    private RealmResource consumerRealm() {
//        return adminClient.realm(bc.consumerRealmName());
//    }
}

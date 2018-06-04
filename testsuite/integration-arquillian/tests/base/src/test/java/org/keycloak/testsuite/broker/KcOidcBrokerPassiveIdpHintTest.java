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

import java.util.List;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.junit.Before;
import org.junit.Test;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.*;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.PublicKeyStorageUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.SuiteContext;
import org.keycloak.testsuite.client.resources.TestingCacheResource;
import org.keycloak.testsuite.util.OAuthClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.keycloak.testsuite.admin.ApiUtil.createUserWithAdminClient;
import static org.keycloak.testsuite.admin.ApiUtil.resetUserPassword;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

/**
 * @author JCoady
 */
public class KcOidcBrokerPassiveIdpHintTest extends AbstractBaseBrokerTest {

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
    	// - createConsumerClients(SuiteContext suiteContext) to OIDC into it
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
    
    @Test
    public void testPassiveIdpHintSuccess() throws Exception {
    	// log in for the first time to set up provider
    	logInAsUserInIDPForFirstTime();
        assertLoggedInAccountManagement();
        logoutFromRealm(bc.consumerRealmName());
    	
        // log in to provider without going through consumer
        logInAsUserToProvider();
        assertLoggedInAccountManagement();
    	
    	// prompt=none&idp_hint=[provider] should log you in to consumer immediately
    	// [provider] = getIDPAlias()
        Assert.fail("test prompt=none");
    }
    
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

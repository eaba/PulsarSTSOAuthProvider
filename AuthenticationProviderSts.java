/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pulsar.broker.authentication;

import java.net.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.*;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.net.SocketAddress;
import java.text.ParseException;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.apache.pulsar.common.api.AuthData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.pulsar.broker.ServiceConfiguration;

public class AuthenticationProviderSts implements AuthenticationProvider{

	private static final String TOKEN_ISSUER_URL = "tokenIssuerUrl";
    private static final String TOKEN_CLIENT_ID = "tokenClientid";
    private static final String TOKEN_ISSUER_JWTS_URL = "tokenIssueJwtsUrl";
 // The token's claim that corresponds to the "role" string
    final static String CONF_TOKEN_AUTH_CLAIM = "tokenAuthClaim";

    Issuer issuer = null;
    ClientID clientID = null;
    JWSAlgorithm jwsAlg = null;
 // When using public key's, the algorithm of the key
    final static String CONF_TOKEN_PUBLIC_ALG = "tokenPublicAlg";
    URL jwkSetURL = null;
    // Create validatr for signed ID tokens
    IDTokenValidator validator = null;
    private String roleClaim;
    
    public void initialize(ServiceConfiguration config) throws IOException 
    {
        if (config.getProperty(TOKEN_ISSUER_URL) != null) {
            issuer = new Issuer((String)config.getProperty(TOKEN_ISSUER_URL));
        } 
        else {
            throw new IOException("No issuer specified");
        }
        if (!StringUtils.isEmpty((String)config.getProperty(TOKEN_CLIENT_ID))) {
            clientID = new ClientID((String)config.getProperty(TOKEN_CLIENT_ID));
        } else {
            throw new IOException("No clientid specified");
        }//
        if (!StringUtils.isEmpty((String)config.getProperty(TOKEN_ISSUER_JWTS_URL))) {
        	jwkSetURL = new URL((String)config.getProperty(TOKEN_ISSUER_JWTS_URL));
        } else {
            throw new IOException("No issuer jwts specified");
        }
        this.roleClaim = getTokenRoleClaim(config);
        jwsAlg = getJWSAlgorithm(config);
        log.info("token issuer: {}", (String)config.getProperty(TOKEN_ISSUER_JWTS_URL));

        
        log.info("token issuer jwts: {}", (String)config.getProperty(TOKEN_ISSUER_JWTS_URL));
        validator = new IDTokenValidator(issuer, clientID, jwsAlg, jwkSetURL);
    }

    public String getAuthMethodName() {
        return "sts";
    }
    private String getTokenRoleClaim(ServiceConfiguration conf) throws IOException {
        if (conf.getProperty(CONF_TOKEN_AUTH_CLAIM) != null
                && StringUtils.isNotBlank((String) conf.getProperty(CONF_TOKEN_AUTH_CLAIM))) {
            return (String) conf.getProperty(CONF_TOKEN_AUTH_CLAIM);
        } else {
            return IDTokenClaimsSet.SUB_CLAIM_NAME;
        }
    }
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        SocketAddress clientAddress;
        String roleToken;

        if (authData.hasDataFromPeer()) {
            clientAddress = authData.getPeerAddress();
        } else {
            throw new AuthenticationException("Authentication data source does not have a client address");
        }

        if (authData.hasDataFromCommand()) 
        {
            roleToken = authData.getCommandData();
        } else 
        {
            throw new AuthenticationException("Authentication data source does not have a role token");
        }

        if (roleToken == null) {
            throw new AuthenticationException("Sts token is null, can't authenticate");
        }
        if (roleToken.isEmpty()) {
            throw new AuthenticationException("Sts RoleToken is empty, Server is Using Sts Authentication");
        }
        if (log.isDebugEnabled()) {
            log.debug("Sts RoleToken : [{}] received from Client: {}", roleToken, clientAddress);
        }

        return getPrincipal(authenticateToken(roleToken));
    }
    private JWSAlgorithm getJWSAlgorithm(ServiceConfiguration conf) throws IllegalArgumentException {
        if (conf.getProperty(CONF_TOKEN_PUBLIC_ALG) != null
                && StringUtils.isNotBlank((String) conf.getProperty(CONF_TOKEN_PUBLIC_ALG))) {
            String alg = (String) conf.getProperty(CONF_TOKEN_PUBLIC_ALG);
            try {
                return JWSAlgorithm.parse(alg);
            } catch (Exception ex) {
                throw new IllegalArgumentException("invalid algorithm provided " + alg, ex);
            }
        } else {
            return JWSAlgorithm.RS256;
        }
    }
    public void close() throws IOException {
    }
    private String getPrincipal(IDTokenClaimsSet jwt) {
        return jwt.getStringClaim(roleClaim);
    }
    @SuppressWarnings("unchecked")
    private IDTokenClaimsSet authenticateToken(final String token) throws AuthenticationException 
    {
    	// Parse the ID token
        JWT idToken = null;
		try {
			idToken = JWTParser.parse(token);
		} catch (ParseException e1) {
			throw new AuthenticationException(e1.getMessage());
		}

        // Set the expected nonce, leave null if none
        Nonce expectedNonce = new Nonce(null); // or null

        IDTokenClaimsSet claims = null;

        try {
            claims = validator.validate(idToken, expectedNonce);
        } catch (BadJOSEException e) {
        	throw new AuthenticationException("Failed to authentication token:"+ e.getMessage());
        } catch (JOSEException e) {
            // Internal processing exception
        }
        return claims;
    }
    public AuthenticationState newAuthState(AuthData authData, SocketAddress remoteAddress, SSLSession sslSession)
            throws AuthenticationException {
        return new StsAuthenticationState(this, authData, remoteAddress, sslSession);
    }
    private static final Logger log = LoggerFactory.getLogger(AuthenticationProviderSts.class);
    private static final class StsAuthenticationState implements AuthenticationState {
        private final AuthenticationProviderSts provider;
        private AuthenticationDataSource authenticationDataSource;
        private IDTokenClaimsSet jwt;
        private final SocketAddress remoteAddress;
        private final SSLSession sslSession;
        private long expiration;

        StsAuthenticationState(AuthenticationProviderSts provider,  AuthData authData,
                SocketAddress remoteAddress,
                SSLSession sslSession) throws AuthenticationException {
            this.provider = provider;
            this.remoteAddress = remoteAddress;
            this.sslSession = sslSession;
            this.authenticate(authData);
        }

        public String getAuthRole() throws AuthenticationException {
            return provider.getPrincipal(jwt);
        }

        public AuthData authenticate(AuthData authData) throws AuthenticationException {
            String token = new String(authData.getBytes(), UTF_8);

            this.jwt = provider.authenticateToken(token);
            this.authenticationDataSource = new AuthenticationDataCommand(token, remoteAddress, sslSession);
            if (jwt.getExpirationTime() != null) {
                this.expiration = jwt.getExpirationTime().getTime();
            } else {
                // Disable expiration
                this.expiration = Long.MAX_VALUE;
            }

            // There's no additional auth stage required
            return null;
        }

        public AuthenticationDataSource getAuthDataSource() {
            return authenticationDataSource;
        }

        public boolean isComplete() {
            // The authentication of tokens is always done in one single stage
            return true;
        }

        public boolean isExpired() {
            return expiration < System.currentTimeMillis();
        }
    }
}

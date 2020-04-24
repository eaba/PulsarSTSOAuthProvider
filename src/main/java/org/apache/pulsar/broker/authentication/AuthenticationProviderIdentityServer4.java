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

import java.io.IOException;
import java.net.SocketAddress;
import java.text.ParseException;

import javax.naming.AuthenticationException;

import org.apache.commons.lang3.StringUtils;
import org.apache.pulsar.broker.authentication.AuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.pulsar.broker.ServiceConfiguration;

public class AuthenticationProviderIdentityServer4 implements AuthenticationProvider{

	private static final String TOKEN_ISSUER_URL = "pulsar.token.issuer.url";
	final static String HTTP_HEADER_NAME = "Authorization";
    final static String HTTP_HEADER_VALUE_PREFIX = "Bearer ";
    private static final String TOKEN_CLIENT_ID = "pulsar.token.clientid";
    private static final String TOKEN_ISSUER_JWTS_URL = "pulsar.token.issuer.jwts.url";
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
    String claim = null;
    
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
        if (!StringUtils.isEmpty((String)config.getProperty(CONF_TOKEN_AUTH_CLAIM))) {
        	claim = (String)config.getProperty(CONF_TOKEN_AUTH_CLAIM);
        } else {
            throw new IOException("No issuer jwts specified");
        }
        jwsAlg = getJWSAlgorithm(config);
        log.info("token issuer: {}", (String)config.getProperty(TOKEN_ISSUER_JWTS_URL));

        
        log.info("token issuer jwts: {}", (String)config.getProperty(TOKEN_ISSUER_JWTS_URL));
        validator = new IDTokenValidator(issuer, clientID, jwsAlg, jwkSetURL);
    }

    public String getAuthMethodName() {
        return "sts";
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
        } else if (authData.hasDataFromHttp()) {
        	String httpHeaderValue = authData.getHttpHeader(HTTP_HEADER_NAME);
            if (httpHeaderValue == null || !httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
                throw new AuthenticationException("Invalid HTTP Authorization header");
            }

            // Remove prefix
            roleToken = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
        } else {
            throw new AuthenticationException("Authentication data source does not have a role token");
        }

        if (roleToken == null) {
            throw new AuthenticationException("Athenz token is null, can't authenticate");
        }
        if (roleToken.isEmpty()) {
            throw new AuthenticationException("Athenz RoleToken is empty, Server is Using Athenz Authentication");
        }
        if (log.isDebugEnabled()) {
            log.debug("Athenz RoleToken : [{}] received from Client: {}", roleToken, clientAddress);
        }

     // Parse the ID token
        JWT idToken = null;
		try {
			idToken = JWTParser.parse(roleToken);
		} catch (ParseException e1) {
			throw new AuthenticationException(e1.getMessage());
		}

        // Set the expected nonce, leave null if none
        Nonce expectedNonce = new Nonce("xyz..."); // or null

        IDTokenClaimsSet claims = null;

        try {
            claims = validator.validate(idToken, expectedNonce);
        } catch (BadJOSEException e) {
        	throw new AuthenticationException(e.getMessage());
        } catch (JOSEException e) {
            // Internal processing exception
        }
       try {
    	   String permission = (String) claims.getClaim("permission");
    	   if(claim == permission)
    		   return roleToken;
    	   else
    		   throw new AuthenticationException("Invalid claim");
       } catch (Exception e) {
    	   throw new AuthenticationException(e.getMessage());
       }
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

    private static final Logger log = LoggerFactory.getLogger(AuthenticationProviderIdentityServer4.class);
}

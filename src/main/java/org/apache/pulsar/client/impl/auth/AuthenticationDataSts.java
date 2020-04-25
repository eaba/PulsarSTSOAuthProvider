package org.apache.pulsar.client.impl.auth;

import java.net.URI;
import org.apache.pulsar.client.api.AuthenticationDataProvider;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

public class AuthenticationDataSts implements AuthenticationDataProvider 
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String refreshToken;
	AuthorizationGrant clientGrant;
	ClientAuthentication clientAuth;
	URI tokenEndpoint;

	public AuthenticationDataSts(String clientid, String clientsecret, String tokenendpoint) throws Exception 
	{
		clientAuth = new ClientSecretBasic(new ClientID(clientid), new Secret(clientsecret));
        clientGrant = new ClientCredentialsGrant();
        tokenEndpoint = new URI(tokenendpoint);
        refreshToken = null;
	}
	public boolean hasDataFromCommand() {
        return true;
    }

    
    public String getCommandData() {
        return getToken();
    }
    public String getRefreshToken() {
        return refreshToken;
    }
    private String getToken() {
        try 
        {
        	if(refreshToken == null)
        	{
        		// The request scope for the token (may be optional)
        		//Scope scope = new Scope("read", "write");
        		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, clientGrant);

            	TokenResponse response = TokenResponse.parse(request.toHTTPRequest().send());

            	if (! response.indicatesSuccess()) {
            	    // We got an error response...
            	    TokenErrorResponse errorResponse = response.toErrorResponse();
            	    throw new RuntimeException(errorResponse.toString());
            	}

            	AccessTokenResponse successResponse = response.toSuccessResponse();

            	// Get the access token

            	refreshToken = successResponse.getTokens().getRefreshToken().toJSONString();
            	return successResponse.getTokens().getAccessToken().toJSONString();
        	}
        	else {
        		RefreshToken refreshtoken = new RefreshToken(this.refreshToken);
        		AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(refreshtoken);
        		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, refreshTokenGrant);

        		TokenResponse response = TokenResponse.parse(request.toHTTPRequest().send());
        		if (! response.indicatesSuccess()) {
        		    // We got an error response...
        		    TokenErrorResponse errorResponse = response.toErrorResponse();
        		    throw new RuntimeException(errorResponse.toString());
        		}

        		AccessTokenResponse successResponse = response.toSuccessResponse();

        		// Get the access token, the refresh token may be updated
        		refreshToken = successResponse.getTokens().getRefreshToken().toJSONString();
        		return successResponse.getTokens().getAccessToken().toJSONString();
        	}
        } catch (Throwable t) {
            throw new RuntimeException("failed to get client token", t);
        }
    }
}

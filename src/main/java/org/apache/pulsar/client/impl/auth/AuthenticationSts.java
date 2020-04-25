package org.apache.pulsar.client.impl.auth;

import java.io.IOException;
import java.util.Map;

import org.apache.pulsar.client.api.Authentication;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.client.api.EncodedAuthenticationParameterSupport;
import org.apache.pulsar.client.api.PulsarClientException;

public class AuthenticationSts implements Authentication, EncodedAuthenticationParameterSupport 
{	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String clientId;
	private String clientSecret;
	String tokenEndpoint;
	public AuthenticationSts(String clientid, String clientsecret, String tokenendpoint) 
	{
		this.clientId = clientid;
		this.clientSecret = clientsecret;
		this.tokenEndpoint = tokenendpoint;
    }
	public AuthenticationDataProvider getAuthData() throws PulsarClientException {
		AuthenticationDataSts data;
		try {
			data = new AuthenticationDataSts(this.clientId, this.clientSecret, this.tokenEndpoint);
		} catch (Exception e) {
			throw new PulsarClientException(e.getMessage());
		}
        return data;
    }
	public void close() throws IOException {
		// TODO Auto-generated method stub
		
	}

	public void configure(String encodedAuthParamString) {
		String[] authParams = encodedAuthParamString.split(",");
		this.clientId = authParams[0];
		this.clientSecret = authParams[1];
		this.tokenEndpoint = authParams[2];
	}

	public void configure(Map<String, String> authParams) {
		// TODO Auto-generated method stub
		
	}

	public String getAuthMethodName() {
		return "sts";
	}

	public void start() throws PulsarClientException {
		// TODO Auto-generated method stub
		
	}

}

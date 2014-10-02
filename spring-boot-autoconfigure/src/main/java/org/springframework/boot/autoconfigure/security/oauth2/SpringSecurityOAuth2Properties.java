/*
 * Copyright 2012-2014 the original author or authors.
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

package org.springframework.boot.autoconfigure.security.oauth2;

import java.util.UUID;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configurable properties for Spring Security OAuth2 auto-configuration
 *
 * @author Greg Turnquist
 */
@ConfigurationProperties(prefix = "spring.security.oauth2")
public class SpringSecurityOAuth2Properties {

	private String resourceId = UUID.randomUUID().toString();

	private String clientId = UUID.randomUUID().toString();

	private String secret = UUID.randomUUID().toString();

	private String[] authorizationTypes = new String[]{ "authorization_code", "implicit", "password" };

	private String[] authorities = new String[]{"USER"};

	private String[] scopes = new String[]{ "read", "write" };

	private String[] redirectUris = new String[]{ "http://localhost:8080/connect/secret" };

	private boolean prePostEnabled = true;
	private boolean securedEnabled = false;
	private boolean jsr250Enabled = false;

	public String getResourceId() {
		return resourceId;
	}

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public String[] getAuthorizationTypes() {
		return authorizationTypes;
	}

	public void setAuthorizationTypes(String[] authorizationTypes) {
		this.authorizationTypes = authorizationTypes;
	}

	public String[] getAuthorities() {
		return authorities;
	}

	public void setAuthorities(String[] authorities) {
		this.authorities = authorities;
	}

	public String[] getScopes() {
		return scopes;
	}

	public void setScopes(String[] scopes) {
		this.scopes = scopes;
	}

	public String[] getRedirectUris() {
		return redirectUris;
	}

	public void setRedirectUris(String[] redirectUris) {
		this.redirectUris = redirectUris;
	}

	public boolean isPrePostEnabled() {
		return prePostEnabled;
	}

	public void setPrePostEnabled(boolean prePostEnabled) {
		this.prePostEnabled = prePostEnabled;
	}

	public boolean isSecuredEnabled() {
		return securedEnabled;
	}

	public void setSecuredEnabled(boolean securedEnabled) {
		this.securedEnabled = securedEnabled;
	}

	public boolean isJsr250Enabled() {
		return jsr250Enabled;
	}

	public void setJsr250Enabled(boolean jsr250Enabled) {
		this.jsr250Enabled = jsr250Enabled;
	}
}

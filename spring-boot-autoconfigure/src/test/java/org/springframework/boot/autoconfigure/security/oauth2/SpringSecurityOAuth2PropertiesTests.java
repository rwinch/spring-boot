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

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.boot.autoconfigure.security.oauth2.SpringSecurityOAuth2Properties;

/**
 * Tests for {@link org.springframework.boot.autoconfigure.security.oauth2.SpringSecurityOAuth2Properties}
 *
 * @author Greg Turnquist
 */
public class SpringSecurityOAuth2PropertiesTests {

	private final SpringSecurityOAuth2Properties properties = new SpringSecurityOAuth2Properties();

	@Test
	public void defaultSettings() {
		assertArrayEquals(properties.getAuthorizationTypes(),
				new String[]{"authorization_code", "implicit", "password"});
		assertEquals(properties.getAuthorities().length, 1);
		assertArrayEquals(properties.getScopes(), new String[]{ "read", "write" });
	}

	@Test
	public void configurableSettings() {
		String resourceId = "testId";
		String clientId = "clientId";
		String secret = "secret";
		properties.setResourceId(resourceId);
		properties.setClientId(clientId);
		properties.setSecret(secret);
		assertEquals(properties.getResourceId(), resourceId);
		assertEquals(properties.getClientId(), clientId);
		assertEquals(properties.getSecret(), secret);
	}

}

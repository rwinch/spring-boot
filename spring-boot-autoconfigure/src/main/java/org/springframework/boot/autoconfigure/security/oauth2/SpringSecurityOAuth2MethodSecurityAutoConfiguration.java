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

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

/**
 * Auto-configure method-level security. Using the configuration properties, switch on the right annotation
 * options.
 *
 * @author Greg Turnquist
 */
@Configuration
@ConditionalOnClass({ OAuth2AccessToken.class })
@ConditionalOnMissingBean(annotation = EnableGlobalMethodSecurity.class)
public class SpringSecurityOAuth2MethodSecurityAutoConfiguration {

	@Configuration
	@EnableGlobalMethodSecurity
	public static class MethodAndAnnotationSecurityConfiguration extends GlobalMethodSecurityConfiguration {

		@Autowired
		SpringSecurityOAuth2Properties config;

		@Override
		protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
			List<MethodSecurityMetadataSource> sources = new ArrayList<MethodSecurityMetadataSource>();
			ExpressionBasedAnnotationAttributeFactory attributeFactory =
					new ExpressionBasedAnnotationAttributeFactory(getExpressionHandler());

			if (config.isPrePostEnabled()) {
				sources.add(new PrePostAnnotationSecurityMetadataSource(attributeFactory));
			}

			if (config.isSecuredEnabled()) {
				sources.add(new SecuredAnnotationSecurityMetadataSource());
			}

			if (config.isJsr250Enabled()) {
				sources.add(new Jsr250MethodSecurityMetadataSource());
			}

			return new DelegatingMethodSecurityMetadataSource(sources);
		}

		@Override
		protected AccessDecisionManager accessDecisionManager() {
			List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
			ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
			expressionAdvice.setExpressionHandler(getExpressionHandler());
			if(config.isPrePostEnabled()) {
				decisionVoters.add(new PreInvocationAuthorizationAdviceVoter(
					expressionAdvice));
			}
			if(config.isJsr250Enabled()) {
				decisionVoters.add(new Jsr250Voter());
			}
			decisionVoters.add(new RoleVoter());
			decisionVoters.add(new AuthenticatedVoter());
			return new AffirmativeBased(decisionVoters);
		}

		@Override
		protected MethodSecurityExpressionHandler createExpressionHandler() {
			return new OAuth2MethodSecurityExpressionHandler();
		}
	}

}

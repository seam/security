package org.jboss.seam.security.external;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.events.PreAuthenticateEvent;
import org.jboss.seam.security.external.configuration.SamlIdentityProvider;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;

public class SamlSingleSignOnSender
{
   @Inject
   private Requests requests;

   @Inject
   private SamlMessageFactory samlMessageFactory;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private BeanManager beanManager;

   public void sendAuthenticationRequestToIDP(HttpServletRequest request, HttpServletResponse response, SamlIdentityProvider samlIdentityProvider, String returnUrl)
   {
      AuthnRequestType authnRequest = samlMessageFactory.createAuthnRequest();
      requests.addRequest(authnRequest.getID(), samlIdentityProvider, returnUrl);

      beanManager.fireEvent(new PreAuthenticateEvent());

      samlMessageSender.sendRequestToIDP(request, response, samlIdentityProvider, SamlProfile.SINGLE_SIGN_ON, authnRequest);
   }
}

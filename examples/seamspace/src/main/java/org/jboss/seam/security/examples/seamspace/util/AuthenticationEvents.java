package org.jboss.seam.security.examples.seamspace.util;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;

import org.jboss.seam.security.events.UserAuthenticatedEvent;
import org.jboss.seam.security.examples.seamspace.model.MemberAccount;

@SessionScoped
public class AuthenticationEvents
{
   private MemberAccount account;
   
   @Produces @Authenticated MemberAccount getAuthenticatedAccount()
   {
      return account;
   }
   
   public void loginSuccessful(@Observes UserAuthenticatedEvent event)
   {
      account = (MemberAccount) event.getUser();
   }
}

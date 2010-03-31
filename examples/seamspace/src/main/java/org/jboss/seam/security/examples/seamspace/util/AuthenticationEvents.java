package org.jboss.seam.security.examples.seamspace.util;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;

import org.jboss.seam.security.events.UserAuthenticatedEvent;
import org.jboss.seam.security.examples.seamspace.model.MemberAccount;

@SessionScoped
class AuthenticationEvents implements Serializable
{
   private static final long serialVersionUID = -2747242953250092889L;
   
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

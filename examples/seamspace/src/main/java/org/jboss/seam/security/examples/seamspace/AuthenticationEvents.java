package org.jboss.seam.security.examples.seamspace;

import javax.inject.Named;

import org.jboss.seam.security.management.JpaIdentityStore;

@Named
public class AuthenticationEvents
{
   //@Observer(JpaIdentityStore.EVENT_USER_AUTHENTICATED)
   public void loginSuccessful(MemberAccount account)
   {
     // Contexts.getSessionContext().set("authenticatedMember", account.getMember());
   }
}

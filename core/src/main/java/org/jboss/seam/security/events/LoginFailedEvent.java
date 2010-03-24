package org.jboss.seam.security.events;

import javax.security.auth.login.LoginException;

/**
 * This event is fired when an authentication attempt fails
 *  
 * @author Shane Bryzak
 */
public class LoginFailedEvent
{
   private LoginException loginException;
   
   public LoginFailedEvent(LoginException loginException)
   {
      this.loginException = loginException;
   }
   
   public LoginException getLoginException()
   {
      return loginException;
   }
}

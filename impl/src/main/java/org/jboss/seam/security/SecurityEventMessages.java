package org.jboss.seam.security;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.enterprise.event.Observes;

import org.jboss.seam.international.status.Messages;
import org.jboss.seam.security.events.AlreadyLoggedInEvent;
import org.jboss.seam.security.events.LoggedInEvent;
import org.jboss.seam.security.events.LoginFailedEvent;
import org.jboss.seam.security.events.NotLoggedInEvent;
import org.jboss.seam.security.events.PostAuthenticateEvent;

/**
 * Produces FacesMessages in response of certain security events, and helps to
 * decouple the Identity component from JSF.
 * 
 * @author Shane Bryzak
 */
public @ApplicationScoped class SecurityEventMessages
{
   private static final String LOGIN_FAILED_MESSAGE_KEY = "org.jboss.seam.loginFailed";
   private static final String LOGIN_SUCCESSFUL_MESSAGE_KEY = "org.jboss.seam.loginSuccessful";
   private static final String ALREADY_LOGGED_IN_MESSAGE_KEY = "org.jboss.seam.alreadyLoggedIn";
   private static final String NOT_LOGGED_IN_MESSAGE_KEY = "org.jboss.seam.notLoggedIn";
   
   private static final String DEFAULT_LOGIN_FAILED_MESSAGE = "Login failed.";
   private static final String DEFAULT_LOGIN_SUCCESSFUL_MESSAGE = "Welcome, {0}.";
   private static final String DEFAULT_ALREADY_LOGGED_IN_MESSAGE = "You're already logged in. Please log out first if you wish to log in again.";
   private static final String DEFAULT_NOT_LOGGED_IN_MESSAGE = "Please log in first.";
   
   @Inject Messages messages;
   @Inject Identity identity;
   
   private boolean enabled = true;
   
   public boolean isEnabled()
   {
      return enabled;
   }
   
   public void setEnabled(boolean value)
   {
      this.enabled = value;
   }      

   public void postAuthenticate(@Observes PostAuthenticateEvent event)
   {
      if (enabled) messages.info(DEFAULT_LOGIN_SUCCESSFUL_MESSAGE, identity.getUser().getId());
   }

   public void addLoginFailedMessage(@Observes LoginFailedEvent event)
   {
      //if (enabled) statusMessages.addFromResourceBundleOrDefault(getLoginFailedMessageSeverity(), getLoginFailedMessageKey(), getDefaultLoginFailedMessage(), event.getLoginException());
   }
   
   public void addLoginSuccessMessage(@Observes LoggedInEvent event)
   {
   //   if (enabled) statusMessages.addFromResourceBundleOrDefault(getLoginSuccessfulMessageSeverity(), getLoginSuccessfulMessageKey(), getDefaultLoginSuccessfulMessage(), credentials.getUsername());
   }
   
   public void addAlreadyLoggedInMessage(@Observes AlreadyLoggedInEvent event)
   {
      //if (enabled) statusMessages.addFromResourceBundleOrDefault(getAlreadyLoggedInMessageSeverity(), getAlreadyLoggedInMessageKey(), getDefaultAlreadyLoggedInMessage());
   }
   
   public void addNotLoggedInMessage(@Observes NotLoggedInEvent event)
   {
      //if (enabled) statusMessages.addFromResourceBundleOrDefault(getNotLoggedInMessageSeverity(), getNotLoggedInMessageKey(), getDefaultNotLoggedInMessage());
   }
   
   // TODO the following methods should probably be moved to the seam-jsf module,
   // or otherwise message severities should be abstracted in seam-international
   
   /*public Severity getLoginFailedMessageSeverity()
   {
      return Severity.INFO;
   }

   public Severity getLoginSuccessfulMessageSeverity()
   {
      return Severity.INFO;
   }
   
   public Severity getAlreadyLoggedInMessageSeverity()
   {
      return Severity.INFO;
   }
      
   public Severity getNotLoggedInMessageSeverity()
   {
      return Severity.WARN;
   }
*/   
   
   public String getLoginFailedMessageKey()
   {
      return LOGIN_FAILED_MESSAGE_KEY;
   }

   public String getDefaultLoginFailedMessage()
   {
      return DEFAULT_LOGIN_FAILED_MESSAGE;
   }
   
   
   public String getLoginSuccessfulMessageKey()
   {
      return LOGIN_SUCCESSFUL_MESSAGE_KEY;
   }

   public String getDefaultLoginSuccessfulMessage()
   {
      return DEFAULT_LOGIN_SUCCESSFUL_MESSAGE;
   }

   public String getAlreadyLoggedInMessageKey()
   {
      return ALREADY_LOGGED_IN_MESSAGE_KEY;
   }
   
   public String getDefaultAlreadyLoggedInMessage()
   {
      return DEFAULT_ALREADY_LOGGED_IN_MESSAGE;
   }
   
   public String getNotLoggedInMessageKey()
   {
      return NOT_LOGGED_IN_MESSAGE_KEY;
   }
   
   public String getDefaultNotLoggedInMessage()
   {
      return DEFAULT_NOT_LOGGED_IN_MESSAGE;
   }

}

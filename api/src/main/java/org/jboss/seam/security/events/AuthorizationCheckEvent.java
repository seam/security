package org.jboss.seam.security.events;

import java.lang.annotation.Annotation;

/**
 * This event may be used to perform an authorization check.  The constructor
 * should be provided with one or more annotation literal values representing the
 * security binding types to be checked.  After firing the event, the isPassed()
 * method should be used to determine whether the authorization check was 
 * successful.
 * 
 * @author Shane Bryzak
 *
 */
public class AuthorizationCheckEvent
{
   private boolean passed;
   private Annotation[] bindings;
   
   public AuthorizationCheckEvent(Annotation... bindings)
   {
      this.bindings = bindings;
   }
   
   public Annotation[] getBindings()
   {
      return bindings;
   }
   
   public void setPassed(boolean value)
   {
      this.passed = value;
   }
   
   public boolean isPassed()
   {
      return passed;
   }
}

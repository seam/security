package org.jboss.seam.security.extension;

import java.lang.annotation.Annotation;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

import org.jboss.seam.security.events.AuthorizationCheckEvent;

/**
 * This event observer 
 * 
 * @author Shane Bryzak
 *
 */
public @ApplicationScoped class AuthorizationObserver
{
   public void observeAuthorizationCheckEvent(@Observes AuthorizationCheckEvent event)
   {
      for (Annotation binding : event.getBindings())
      {
         
      }
   }
}

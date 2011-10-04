package org.jboss.seam.security.events;

import org.jboss.seam.security.session.Session;

/**
 * This event is raised when the session has been invalidated
 * 
 * @author george
 * 
 */
public class SessionInvalidatedEvent
{
   private Session session;

   public SessionInvalidatedEvent(Session session)
   {
      super();
      this.session = session;
   }

   public Session getSession()
   {
      return session;
   }
}

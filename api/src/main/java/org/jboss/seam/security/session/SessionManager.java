package org.jboss.seam.security.session;

/**
 * Session Manager
 * 
 * @author George Gastaldi
 * 
 */
public interface SessionManager
{
   public void register(Session session);

   public Session unregister(String id);

   public boolean isSessionValid(String sessionId);

   public void invalidateSession(String sessionId);
}

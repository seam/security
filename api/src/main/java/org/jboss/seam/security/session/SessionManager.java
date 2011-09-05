package org.jboss.seam.security.session;

public interface SessionManager
{
   public void register(Session session);

   public Session unregister(String id);

   public boolean isSessionRegistered(String id);

}

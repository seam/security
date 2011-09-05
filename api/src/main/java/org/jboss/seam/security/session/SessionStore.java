package org.jboss.seam.security.session;

import java.util.List;

public interface SessionStore
{
   public void persist(Session session);

   public void remove(Session session);

   public void refresh(Session session);

   public Session findById(String id);

   public List<Session> findAllSessions();

   public boolean sessionExists(String id);
}

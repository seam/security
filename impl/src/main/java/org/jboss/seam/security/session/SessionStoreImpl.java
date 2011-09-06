package org.jboss.seam.security.session;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

public class SessionStoreImpl implements SessionStore
{
   private HashMap<String, Session> sessionMap = new HashMap<String, Session>();

   @Override
   public void persist(Session session)
   {
      sessionMap.put(session.getId(), session);
   }

   @Override
   public void remove(Session session)
   {
      sessionMap.remove(session.getId());
   }

   @Override
   public Session findById(String sessionId)
   {
      return sessionMap.get(sessionId);
   }

   @Override
   public Collection<Session> findAllSessions()
   {
      return Collections.unmodifiableCollection(sessionMap.values());
   }
}

package org.jboss.seam.security.session;

import java.util.Collection;

/**
 * Store where {@link Session} objects are stored/retrieved.
 * 
 * @author George Gastaldi
 * 
 */
public interface SessionStore
{
   /**
    * Persists the session in the current store
    * 
    * @param session
    */
   public void persist(Session session);

   /**
    * Removes the session in this store
    * 
    * @param session
    */
   public void remove(Session session);

   /**
    * Searchs the Session for the specified ID
    * 
    * @param id
    * @return
    */
   public Session findById(String sessionId);

   /**
    * Finds all sessions related to this store
    * 
    * @return
    */
   public Collection<Session> findAllSessions();

}
package org.jboss.seam.security.session;

import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.jboss.seam.security.events.SessionInvalidatedEvent;
import org.jboss.solder.servlet.event.Destroyed;
import org.jboss.solder.servlet.event.Initialized;

public class SessionManagerImpl implements SessionManager
{

   @Inject
   private SessionStore sessionStore;

   @Inject
   private BeanManager beanManager;

   @Override
   public void register(Session session)
   {
      sessionStore.persist(session);
   }

   @Override
   public Session unregister(String id)
   {
      Session session = sessionStore.findById(id);
      if (session != null)
      {
         sessionStore.remove(session);
      }
      return session;
   }

   @Override
   public void invalidateSession(String sessionId)
   {
      Session session = sessionStore.findById(sessionId);
      if (session != null)
      {
         session.invalidate();
         sessionStore.persist(session);
      }
   }

   @Override
   public boolean isSessionValid(String sessionId)
   {
      Session session = sessionStore.findById(sessionId);
      if (session != null)
      {
         return session.isValid();
      }
      return false;
   }

   /**
    * Registering a new session
    * 
    * @param session
    * @throws UnknownHostException
    */
   void sessionInit(@Observes @Initialized HttpSession httpSession, HttpServletRequest request)
            throws UnknownHostException
   {
      Session session = new SessionImpl(httpSession, InetAddress.getByName(request.getRemoteAddr()));
      register(session);
   }

   void sessionDestroyed(@Observes @Destroyed HttpSession session)
   {
      unregister(session.getId());
   }

   void requestInit(@Observes @Initialized HttpServletRequest request)
   {
      HttpSession httpSession = request.getSession(false);
      if (httpSession != null)
      {
         Session session = sessionStore.findById(httpSession.getId());
         if (session == null)
         {
            // Session has not been registered on the session store
         }
         else if (!session.isValid())
         {
            // session is marked as invalid. invalidate this session now.
            httpSession.invalidate();
            beanManager.fireEvent(new SessionInvalidatedEvent(session));
         }
         else
         {
            session.updateSessionValues(httpSession);
            sessionStore.persist(session);
         }
      }
   }
}

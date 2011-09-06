package org.jboss.seam.security.session;

import java.net.InetAddress;

import javax.servlet.http.HttpSession;

public class SessionImpl implements Session
{
   private String id;
   private long creationTime;
   private long lastAccessedTime;
   private InetAddress userAddress;

   public String getId()
   {
      return id;
   }

   public SessionImpl(HttpSession httpSession, InetAddress userAddress)
   {
      this.id = httpSession.getId();
      this.creationTime = httpSession.getCreationTime();
      this.lastAccessedTime = httpSession.getLastAccessedTime();
      this.userAddress = userAddress;
   }

   public long getCreationTime()
   {
      return creationTime;
   }

   public long getLastAccessedTime()
   {
      return lastAccessedTime;
   }

   public InetAddress getUserAddress()
   {
      return userAddress;
   }

   @Override
   public void invalidate()
   {
      // TODO Auto-generated method stub

   }

   @Override
   public boolean isValid()
   {
      return false;
   }

   @Override
   public void updateSessionValues(Object sessionObj)
   {
      HttpSession session = (HttpSession) sessionObj;
      this.lastAccessedTime = session.getLastAccessedTime();
   }
}

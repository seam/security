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
      // TODO Auto-generated method stub
      return false;
   }

   @Override
   public void updateSessionValues(Object sessionObj)
   {
      HttpSession session = (HttpSession) sessionObj;
      this.lastAccessedTime = session.getLastAccessedTime();
   }
}

package org.jboss.seam.security.session;

import java.net.InetAddress;

/**
 * Period of activity between a user logging in and logging out of a (multi-user) system
 * 
 * @author George Gastaldi
 * 
 */
public interface Session
{
   public String getId();

   public long getCreationTime();

   public long getLastAccessedTime();

   public InetAddress getUserAddress();

   public boolean isValid();

   public void invalidate();

   public void updateSessionValues(Object sessionObj);
}

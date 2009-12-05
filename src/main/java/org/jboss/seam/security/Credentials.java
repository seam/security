package org.jboss.seam.security;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.events.CredentialsInitializedEvent;
import org.jboss.seam.security.events.CredentialsUpdatedEvent;

@Named//("org.jboss.seam.security.credentials")
@SessionScoped
public class Credentials implements Serializable
{
   private static final long serialVersionUID = -2271248957776488426L;
   
   @Inject BeanManager manager;
   
   private String username;
   private String password;
   
   private boolean invalid;
   
   private boolean initialized;
   
   public Credentials() {}
   
   public boolean isInitialized()
   {
      return initialized;
   }
   
   public void setInitialized(boolean initialized)
   {
      this.initialized = initialized;
   }
   
   public String getUsername()
   {
      if (!isInitialized())
      {
         setInitialized(true);
         manager.fireEvent(new CredentialsInitializedEvent(this));
      }
      
      return username;
   }
   
   public void setUsername(String username)
   {
      if (this.username != username && (this.username == null || !this.username.equals(username)))
      {
         this.username = username;
         invalid = false;
         manager.fireEvent(new CredentialsUpdatedEvent());
      }
   }
   
   public String getPassword()
   {
      return password;
   }
   
   public void setPassword(String password)
   {
      if (this.password != password && (this.password == null || !this.password.equals(password)))
      {
         this.password = password;
         invalid = false;
         manager.fireEvent(new CredentialsUpdatedEvent());
      }
   }
   
   public boolean isSet()
   {
      return getUsername() != null && password != null;
   }
   
   public boolean isInvalid()
   {
      return invalid;
   }
   
   public void invalidate()
   {
      invalid = true;
   }
   
   public void clear()
   {
      username = null;
      password = null;
      initialized = false;
   }
   
   @Override
   public String toString()
   {
      return "Credentials[" + username + "]";
   }
}

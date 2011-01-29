package org.jboss.seam.security.external.openid;

import java.util.Map;

import org.jboss.security.auth.spi.Users.User;

/**
 * Represents a user authenticated using OpenID
 * 
 * @author Shane Bryzak
 */
public class OpenIdUser extends User
{
   private String identifier;
   private String openIdProvider;
   private Map<String,String> attributes;
   
   public String getIdentifier()
   {
      return identifier;
   }
   
   public void setIdentifier(String identifier)
   {
      this.identifier = identifier;
   }
   
   public String getOpenIdProvider()
   {
      return openIdProvider;
   }
   
   public void setOpenIdProvider(String openIdProvider)
   {
      this.openIdProvider = openIdProvider;
   }
   
   public Map<String,String> getAttributes()
   {
      return attributes;
   }
   
   public void setAttributes(Map<String,String> attributes)
   {
      this.attributes = attributes;
   }
}

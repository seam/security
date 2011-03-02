package org.jboss.seam.security.external.openid.providers;

import javax.enterprise.inject.Model;

/**
 * 
 * @author Shane Bryzak
 *
 */
public @Model class CustomOpenIdProvider implements OpenIdProvider
{
   public static final String CODE = "custom";
   
   private String url;
   
   public void setUrl(String url)
   {
      this.url = url;
   }
   
   public String getCode()
   {
      return CODE;
   }
   
   public String getName()
   {
      return "Custom";
   }
   
   public String getUrl()
   {
      return url;
   }
}

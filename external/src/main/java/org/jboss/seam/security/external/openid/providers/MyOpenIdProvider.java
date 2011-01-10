package org.jboss.seam.security.external.openid.providers;

/**
 * Open ID provider for myopenid.com
 * 
 * @author Shane Bryzak
 *
 */
public class MyOpenIdProvider implements OpenIdProvider
{
   public static final String CODE = "myopenid";
   
   public String getCode()
   {
      return CODE;
   }
   
   public String getName()
   {
      return "MyOpenID";
   }
   
   public String getUrl()
   {
      return "https://myopenid.com";
   }

}

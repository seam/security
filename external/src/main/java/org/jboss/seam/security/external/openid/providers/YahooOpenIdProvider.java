package org.jboss.seam.security.external.openid.providers;

/**
 * Open ID provider for Yahoo accounts
 * 
 * @author Shane Bryzak
 *
 */
public class YahooOpenIdProvider implements OpenIdProvider
{
   public static final String CODE = "yahoo";
   
   public String getCode()
   {
      return CODE;
   }
   
   public String getName()
   {
      return "Yahoo";
   }
   
   public String getUrl()
   {
      return "https://me.yahoo.com";
   }

}

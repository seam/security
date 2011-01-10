package org.jboss.seam.security.external.openid;

import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.Model;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.openid.providers.OpenIdProvider;

/**
 * 
 * @author Shane Bryzak
 *
 */
public @Model class OpenIdAuthenticator implements Authenticator
{
   private String openIdProviderUrl;
   
   //private OpenIdProvider provider;
   
   @Inject private OpenIdRelyingPartyApi openIdApi;
   
   @Inject List<OpenIdProvider> providers;
   
   private String providerCode;
   
   public String getProviderCode()
   {
      return providerCode;
   }
   
   public void setProviderCode(String providerCode)
   {
      this.providerCode = providerCode;
   }
   
   public String getOpenIdProviderUrl()
   {
      return openIdProviderUrl;
   }
   
   public void setOpenIdProviderUrl(String openIdProviderUrl)
   {
      this.openIdProviderUrl = openIdProviderUrl;
   }
   
   protected OpenIdProvider getSelectedProvider()
   {
      if (providerCode != null)
      {
         for (OpenIdProvider provider : providers)
         {
            if (providerCode.equals(provider.getCode())) return provider;
         }
      }
      return null;
   }
   
   public AuthStatus authenticate()
   {
      List<OpenIdRequestedAttribute> attributes = new LinkedList<OpenIdRequestedAttribute>();
      attributes.add(openIdApi.createOpenIdRequestedAttribute("email", "http://schema.openid.net/contact/email", false, null));
      
      OpenIdProvider selectedProvider = getSelectedProvider();
      
      openIdApi.login(selectedProvider != null ? selectedProvider.getUrl() : getOpenIdProviderUrl(), 
            attributes, (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());      
      
      return AuthStatus.DEFERRED;
   }
   
   public List<OpenIdProvider> getProviders()
   {
      return providers;
   }

}

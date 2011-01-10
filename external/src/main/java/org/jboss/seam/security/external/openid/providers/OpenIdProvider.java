package org.jboss.seam.security.external.openid.providers;

/**
 * Base interface for defining a set of built in Open ID providers
 * 
 * @author Shane Bryzak
 *
 */
public interface OpenIdProvider
{
   String getCode();
   String getName();
   String getUrl();
}

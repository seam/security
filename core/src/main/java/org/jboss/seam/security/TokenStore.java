package org.jboss.seam.security;

/**
 * A store containing user authentication tokens.  Used in conjunction with the RememberMe
 * component to auto-login users that present a valid cookie-based token.
 * 
 * @author Shane Bryzak
 */
public interface TokenStore
{
   void createToken(String username, String value);
   boolean validateToken(String username, String value);
   void invalidateToken(String username, String value);
   void invalidateAll(String username);
}

package org.jboss.seam.security.permission;

/**
 * Strategy for generating permission target identifiers.
 *  
 * @author Shane Bryzak
 */
public interface IdentifierStrategy
{
   boolean canIdentify(Class targetClass);
   String getIdentifier(Object target);
}

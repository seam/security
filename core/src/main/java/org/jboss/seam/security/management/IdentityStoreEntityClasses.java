package org.jboss.seam.security.management;

import javax.enterprise.context.ApplicationScoped;

/**
 * FIXME a hack until we get some proper bean configuration
 * 
 * @author Shane Bryzak
 *
 */
@ApplicationScoped
public interface IdentityStoreEntityClasses
{
   Class<?> getUserEntityClass();
   Class<?> getRoleEntityClass();
}

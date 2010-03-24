package org.jboss.seam.security.annotations;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Used to restrict access to a Seam component, component method or entity.
 * 
 * @see org.jboss.seam.security.Identity
 *
 * @author Shane Bryzak
 */
@Target({TYPE,METHOD})
@Documented
@Retention(RUNTIME)
@Inherited
public @interface Restrict 
{
   /**
    * Restrictions may be expressed using any EL expression, and usually
    * include the use of s:hasRole(...) or s:hasPermission(..., /..).
    * If no EL expression is explicitly specified, Seam security defaults
    * the permission to be checked.
    * 
    * @return An EL expression that defines the restriction to be checked
    */
   String value() default "";
}

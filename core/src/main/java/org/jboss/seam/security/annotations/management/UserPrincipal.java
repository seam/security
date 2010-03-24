package org.jboss.seam.security.annotations.management;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Flags an entity field or method as representing the principal (username) for a user
 *  
 * @author Shane Bryzak
 */
@Target({METHOD,FIELD})
@Documented
@Retention(RUNTIME)
@Inherited
public @interface UserPrincipal
{

}

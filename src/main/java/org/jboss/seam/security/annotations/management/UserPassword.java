package org.jboss.seam.security.annotations.management;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Flags an entity field or method as representing the password for a user
 *  
 * @author Shane Bryzak
 */
@Target({METHOD,FIELD})
@Documented
@Retention(RUNTIME)
@Inherited
public @interface UserPassword
{   
   /**
    * The hash algorithm, only used if there is no @PasswordSalt property specified
    */
   String hash() default "";
   
   /**
    * Number of iterations for generating the password hash
    */
   int iterations() default 1000;
}

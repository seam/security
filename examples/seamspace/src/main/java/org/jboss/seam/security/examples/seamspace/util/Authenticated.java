package org.jboss.seam.security.examples.seamspace.util;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

@Target({FIELD, METHOD})
@Retention(RUNTIME)
@Qualifier
public @interface Authenticated
{

}

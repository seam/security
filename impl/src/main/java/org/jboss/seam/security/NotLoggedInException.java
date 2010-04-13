package org.jboss.seam.security;

//import javax.ejb.ApplicationException;

/**
 * Thrown when an unauthenticated user attempts to execute a restricted action. 
 * 
 * @author Shane Bryzak
 */
//@ApplicationException(rollback=true)
public class NotLoggedInException extends SecurityException {}

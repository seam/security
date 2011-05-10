package org.jboss.seam.security;

/**
 * Thrown when an unauthenticated user attempts to execute a restricted action.
 *
 * @author Shane Bryzak
 */
public class NotLoggedInException extends SecurityException {
    private static final long serialVersionUID = -2708471484839030465L;
}

package org.jboss.seam.security.examples.authorization.exception;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

import org.jboss.solder.exception.control.CaughtException;
import org.jboss.solder.exception.control.Handles;
import org.jboss.solder.exception.control.HandlesExceptions;
import org.jboss.seam.security.AuthorizationException;

/**
 * Handles user authorization exceptions
 *
 * @author Shane Bryzak
 */
@HandlesExceptions
public class ExceptionHandler {
    @Inject
    FacesContext facesContext;

    public void handleAuthorizationException(@Handles CaughtException<AuthorizationException> evt) {
        facesContext.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                "You do not have the necessary permissions to perform that operation", ""));
        evt.handled();
    }
}

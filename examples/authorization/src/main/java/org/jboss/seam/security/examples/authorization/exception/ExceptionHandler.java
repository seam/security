package org.jboss.seam.security.examples.authorization.exception;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;

import org.jboss.seam.exception.control.CaughtException;
import org.jboss.seam.exception.control.Handles;
import org.jboss.seam.exception.control.HandlesExceptions;
import org.jboss.seam.exception.filter.StackFrame;
import org.jboss.seam.exception.filter.StackFrameFilter;
import org.jboss.seam.exception.filter.StackFrameFilterResult;
import org.jboss.seam.security.AuthorizationException;

/**
 * Handles user authorization exceptions
 * 
 * @author Shane Bryzak
 *
 */
@HandlesExceptions
public class ExceptionHandler
{
   @Inject FacesContext facesContext;
   
   final StackFrameFilter<AuthorizationException> filter = new StackFrameFilter<AuthorizationException>() {
      @Override
      public StackFrameFilterResult process(StackFrame frame) {
          return StackFrameFilterResult.TERMINATE_AFTER;
      }
  };
   
   public void handleAuthorizationException(@Handles CaughtException<AuthorizationException> evt)
   {
      facesContext.addMessage(null, new FacesMessage(
            "You do not have the necessary permissions to perform that operation"));
      evt.handled();
      
      //filter.process(evt.getExceptionStack());
   }
}

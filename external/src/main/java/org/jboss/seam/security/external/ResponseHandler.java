package org.jboss.seam.security.external;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;

import javax.inject.Inject;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.saml.SamlMessage;
import org.jboss.seam.security.external.saml.SamlPostMessage;
import org.jboss.seam.security.external.saml.SamlRedirectMessage;

/**
 * @author Marcel Kolsteren
 * 
 */
public class ResponseHandler
{
   @Inject
   private ResponseHolder responseHolder;

   public void sendFormToUserAgent(String destination, SamlPostMessage message)
   {
      String key = message.getRequestOrResponse().isRequest() ? SamlMessage.QSP_SAML_REQUEST : SamlMessage.QSP_SAML_RESPONSE;

      if (destination == null)
         throw new IllegalStateException("Destination is null");

      StringBuilder builder = new StringBuilder();

      builder.append("<HTML>");
      builder.append("<HEAD>");
      if (message.getRequestOrResponse().isRequest())
         builder.append("<TITLE>HTTP Post SamlBinding (Request)</TITLE>");
      else
         builder.append("<TITLE>HTTP Post SamlBinding Response (Response)</TITLE>");

      builder.append("</HEAD>");
      builder.append("<BODY Onload=\"document.forms[0].submit()\">");

      builder.append("<FORM METHOD=\"POST\" ACTION=\"" + destination + "\">");
      builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"" + key + "\"" + " VALUE=\"" + message.getSamlMessage() + "\"/>");
      if (message.getRelayState() != null)
      {
         builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"" + SamlMessage.QSP_RELAY_STATE + "\"" + " VALUE=\"" + message.getRelayState() + "\"/>");
      }
      builder.append("</FORM></BODY></HTML>");

      PrintWriter writer = getWriter();
      writer.print(builder.toString());
      writer.flush();
   }

   public void sendHttpRedirectToUserAgent(String url)
   {
      try
      {
         responseHolder.getResponse().sendRedirect(url);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void sendHttpRedirectToUserAgent(String location, SamlRedirectMessage redirectMessage)
   {
      String url = location + "?" + redirectMessage.createQueryString();
      sendHttpRedirectToUserAgent(url);
   }

   public void sendError(int statusCode, String message)
   {
      try
      {
         responseHolder.getResponse().sendError(statusCode, message);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   private PrintWriter getWriter()
   {
      try
      {
         return responseHolder.getResponse().getWriter();
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public Writer getWriter(String mimeType)
   {
      responseHolder.getResponse().setContentType(mimeType);
      return getWriter();
   }
}

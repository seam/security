package org.jboss.seam.security.externaltest.integration.openid.rp;

import java.io.IOException;
import java.util.Enumeration;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;

@WebServlet(name = "RpTestServlet", urlPatterns = { "/testservlet" })
public class RpTestServlet extends HttpServlet
{
   private static final long serialVersionUID = -4551548646707243449L;

   @Inject
   private OpenIdRpApplicationMock openIdRpApplicationMock;

   @Inject
   private ResponseHolder responseHolder;

   @Override
   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      responseHolder.setResponse(response);
      String command = request.getParameter("command");
      if (command.equals("login"))
      {
         String identifier = request.getParameter("identifier");
         boolean fetchEmail = Boolean.parseBoolean(request.getParameter("fetchEmail"));
         openIdRpApplicationMock.login(identifier, fetchEmail);
      }
      else if (command.equals("getNrOfDialogues"))
      {
         int count = 0;
         Enumeration<String> attributeNames = request.getServletContext().getAttributeNames();
         while (attributeNames.hasMoreElements())
         {
            String attributeName = attributeNames.nextElement();
            if (attributeName.startsWith("DialogueContextBeanStore"))
            {
               count++;
            }
         }
         response.getWriter().print(count);
      }
      else
      {
         throw new RuntimeException("Invalid command: " + command);
      }
   }
}

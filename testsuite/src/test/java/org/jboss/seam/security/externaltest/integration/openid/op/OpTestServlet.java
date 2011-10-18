package org.jboss.seam.security.externaltest.integration.openid.op;

import java.io.IOException;
import java.util.Enumeration;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "OpTestServlet", urlPatterns = {"/testservlet"})
public class OpTestServlet extends HttpServlet {
    private static final long serialVersionUID = -4551548646707243449L;

    @Inject
    private OpenIdProviderApplicationMock openIdProviderApplicationMock;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String command = request.getParameter("command");
        if (command.equals("authenticate")) {
            String userName = request.getParameter("userName");
            openIdProviderApplicationMock.handleLogin(userName, response);
        } else if (command.equals("setAttribute")) {
            String email = request.getParameter("email");
            openIdProviderApplicationMock.setAttribute("email", email, response);
        } else if (command.equals("getNrOfDialogues")) {
            int count = 0;
            Enumeration<String> attributeNames = request.getServletContext().getAttributeNames();
            while (attributeNames.hasMoreElements()) {
                String attributeName = attributeNames.nextElement();
                if (attributeName.startsWith("DialogueContextBeanStore")) {
                    count++;
                }
            }
            response.getWriter().print(count);
        } else {
            throw new RuntimeException("Invalid command: " + command);
        }
    }
}

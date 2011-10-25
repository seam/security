package org.jboss.seam.security.externaltest.integration.saml.idp;

import java.io.IOException;
import java.util.Enumeration;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.externaltest.integration.MetaDataLoader;

@WebServlet(name = "IdpTestServlet", urlPatterns = {"/testservlet"})
public class IdpTestServlet extends HttpServlet {
    private static final long serialVersionUID = -4551548646707243449L;

    @Inject
    private SamlIdpApplicationMock samlIdpApplicationMock;

    @Inject
    private MetaDataLoader metaDataLoader;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String command = request.getParameter("command");
        if (command.equals("authenticate")) {
            samlIdpApplicationMock.handleLogin(request.getParameter("userName"), response);
        } else if (command.equals("singleLogout")) {
            samlIdpApplicationMock.handleSingleLogout(response);
        } else if (command.equals("getNrOfSessions")) {
            response.getWriter().print(samlIdpApplicationMock.getNumberOfSessions());
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
        } else if (command.equals("loadMetaData")) {
            metaDataLoader.loadMetaDataOfOtherSamlEntity("www.sp1.com", "sp");
            metaDataLoader.loadMetaDataOfOtherSamlEntity("www.sp2.com", "sp");
        } else {
            throw new RuntimeException("Invalid command: " + command);
        }
    }
}

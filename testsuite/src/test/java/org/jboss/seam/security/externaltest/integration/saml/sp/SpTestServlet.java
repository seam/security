package org.jboss.seam.security.externaltest.integration.saml.sp;

import java.io.IOException;
import java.util.Enumeration;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.externaltest.integration.MetaDataLoader;

@WebServlet(name = "SpTestServlet", urlPatterns = {"/testservlet"})
public class SpTestServlet extends HttpServlet {
    private static final long serialVersionUID = -4551548646707243449L;

    @Inject
    private SamlSpApplicationMock samlSpApplicationMock;

    @Inject
    private MetaDataLoader metaDataLoader;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String command = request.getParameter("command");
        if (command.equals("login")) {
            String idpEntityId = request.getParameter("idpEntityId");
            samlSpApplicationMock.login(idpEntityId, response);
        } else if (command.equals("singleLogout")) {
            samlSpApplicationMock.handleGlobalLogout(response);
        } else if (command.equals("getNrOfSessions")) {
            response.getWriter().print(samlSpApplicationMock.getNumberOfSessions());
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
            metaDataLoader.loadMetaDataOfOtherSamlEntity("www.idp.com", "idp");
        } else {
            throw new RuntimeException("Invalid command: " + command);
        }
    }
}

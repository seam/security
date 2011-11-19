/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an &quot;AS IS&quot; BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.seam.security.test.server.identity;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.picketlink.idm.impl.api.PasswordCredential;

/**
 * @author <a href="http://community.jboss.org/people/LightGuard">Jason Porter</a>
 */
@WebServlet(name = "LogoutServlet", loadOnStartup = 1, urlPatterns = { "/logout" })
public class LogoutServlet extends HttpServlet {
    @Inject
    private Credentials creds;

    @Inject
    private Identity identity;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        creds.setCredential(new PasswordCredential("test"));
        creds.setUsername("test");

        identity.login();

        if (identity.isLoggedIn())
            resp.getOutputStream().print("loggedIn");
        else
            resp.getOutputStream().print("not loggedIn");

        resp.getOutputStream().flush();
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        identity.logout();

        if (!identity.isLoggedIn() && !req.isRequestedSessionIdValid())
            resp.getOutputStream().print("loggedOut and session invalidated");
        else if (req.isRequestedSessionIdValid())
            resp.getOutputStream().print("session still valid");
        else if (identity.isLoggedIn() && !req.isRequestedSessionIdValid())
            resp.getOutputStream().print("still loggedIn, session invalidated");

        resp.getOutputStream().flush();
    }
}

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
import java.net.URL;

import javax.inject.Inject;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.test.BasicArchiveBuilder;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.solder.servlet.http.HttpSessionStatus;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author <a href="http://community.jboss.org/people/LightGuard">Jason Porter</a>
 */
@RunWith(Arquillian.class)
public class LogoutTest {

    @Inject
    private Identity identity;

    @Inject
    private Credentials credential;

    private HttpSessionStatus httpSessionStatus;

    @Deployment(testable = false)
    public static Archive<?> createTestArchive() {
        WebArchive war = BasicArchiveBuilder.baseArchive("logoutTest", true);

        war.addClasses(SimpleAuthenticator.class, LogoutServlet.class);
        war.addAsWebInfResource("WEB-INF/logouttest-seam-beans.xml", "classes/META-INF/seam-beans.xml");

        return war;
    }

    /**
     * Test for SEAMSECURITY-83
     */
    @Test
    public void assertLogoutInvalidatesSession(@ArquillianResource(LogoutServlet.class) URL baseUrl) throws IOException {
        final HttpClient client = new HttpClient();

        final PostMethod put = new PostMethod(baseUrl.toString() + "logout");
        client.executeMethod(put);

        assertThat(put.getResponseBodyAsString(), is("loggedIn"));

        final DeleteMethod delete = new DeleteMethod(baseUrl.toString() + "logout");
        client.executeMethod(delete);

        assertThat(delete.getResponseBodyAsString(), is("loggedOut and session invalidated"));
    }
}

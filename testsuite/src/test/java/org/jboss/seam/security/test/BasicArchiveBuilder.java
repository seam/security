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

package org.jboss.seam.security.test;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.DependencyResolvers;
import org.jboss.shrinkwrap.resolver.api.maven.MavenDependencyResolver;

/**
 * @author <a href="http://community.jboss.org/people/LightGuard">Jason Porter</a>
 */
public class BasicArchiveBuilder {
    public static WebArchive baseArchive(final String archiveName, boolean includeBeansXml) {
        WebArchive war = ShrinkWrap.create(WebArchive.class, archiveName + ".war");

        war.addAsLibraries(DependencyResolvers.use(MavenDependencyResolver.class)
                .loadMetadataFromPom("pom.xml")
                .artifact("org.jboss.solder:solder-impl")
                .artifact("org.jboss.seam.security:seam-security")
                .artifact("org.jboss.seam.transaction:seam-transaction")
                .artifact("joda-time:joda-time:1.6.2") // I think there's a bug here with modular servers
                .resolveAs(JavaArchive.class));

        if (includeBeansXml)
            war.addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");

        return war;
    }
}

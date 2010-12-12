/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.seam.security.externaltest.integration.client;

import java.util.HashMap;
import java.util.Map;

import javax.enterprise.inject.spi.Extension;

import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.DialogueContextExtension;
import org.jboss.seam.security.external.virtualapplications.VirtualApplicationContextExtension;
import org.jboss.seam.security.externaltest.integration.MetaDataLoader;
import org.jboss.seam.security.externaltest.integration.openid.op.OpCustomizer;
import org.jboss.seam.security.externaltest.integration.openid.rp.RpCustomizer;
import org.jboss.seam.security.externaltest.integration.saml.idp.IdpCustomizer;
import org.jboss.seam.security.externaltest.integration.saml.sp.SpCustomizer;
import org.jboss.seam.security.externaltest.util.MavenArtifactResolver;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;

class ArchiveBuilder
{
   static WebArchive idpArchive;

   static WebArchive spArchive;

   static Map<String, WebArchive> webArchives = new HashMap<String, WebArchive>();

   static WebArchive getArchive(String entity)
   {
      WebArchive webArchive = webArchives.get(entity);
      if (webArchive == null)
      {
         webArchive = createTestArchive(entity);
         webArchives.put(entity, webArchive);
      }
      return webArchive;
   }

   static private WebArchive createTestArchive(String entity)
   {
      WebArchive war = ShrinkWrap.create(WebArchive.class, entity + ".war");

      war.addLibraries(MavenArtifactResolver.resolve("org.jboss.seam.servlet:seam-servlet-impl"));
      war.addLibraries(MavenArtifactResolver.resolve("org.jboss.seam.servlet:seam-servlet-api"));
      war.addLibraries(MavenArtifactResolver.resolve("org.openid4java", "openid4java"));
      war.addLibraries(MavenArtifactResolver.resolve("nekohtml", "nekohtml"));
      war.addLibraries(MavenArtifactResolver.resolve("org.jboss.weld:weld-extensions"));
      war.addLibraries(MavenArtifactResolver.resolve("commons-httpclient:commons-httpclient"));

      war.addWebResource("WEB-INF/" + entity + "-beans.xml", "beans.xml");
      war.addWebResource("WEB-INF/context.xml", "context.xml");

      war.addPackage(MetaDataLoader.class.getPackage());
      if (entity.equals("sp"))
      {
         war.addPackage(SpCustomizer.class.getPackage());
         war.addWebResource("test_keystore.jks");
      }
      else if (entity.equals("idp"))
      {
         war.addPackage(IdpCustomizer.class.getPackage());
         war.addWebResource("test_keystore.jks");
      }
      else if (entity.equals("op"))
      {
         war.addPackage(OpCustomizer.class.getPackage());
      }
      else if (entity.equals("rp"))
      {
         war.addPackage(RpCustomizer.class.getPackage());
      }

      war.addLibrary(createJarModule());

      return war;
   }

   private static JavaArchive createJarModule()
   {
      JavaArchive jar = ShrinkWrap.create(JavaArchive.class, "test.jar");

      // Add the package "org.jboss.seam.security.external" and all its
      // subpackages.
      jar.addPackages(true, ResponseHandler.class.getPackage());

      jar.addResource("META-INF/beans.xml", "META-INF/beans.xml");
      jar.addResource("META-INF/web-fragment.xml", "META-INF/web-fragment.xml");
      jar.addServiceProvider(Extension.class, VirtualApplicationContextExtension.class, DialogueContextExtension.class);

      return jar;
   }
}

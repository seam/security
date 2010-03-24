Seam Security 3.0.0 Beta 1
==========================

Seam Security provides a number of features for securing your CDI-based application.


Contents of distribution
========================

doc/

  API Docs and reference guide.
  
examples/

  Seam Security Examples
  
lib/

  Seam Security jar files
  
Licensing
=========

This distribution, as a whole, is licensed under the terms of the GNU Lesser General Public License
(LGPL) Version 2.1, the text of which is contained in the file lgpl.txt.

Seam Security URLs
==================

Seam Framework Home Page:      http://www.seamframework.org
Downloads:                     http://www.seamframework.org/Download/SeamDownloads
Forums:                        http://www.seamframework.org/Community/SeamUsers
Source Code:                   http://anonsvn.jboss.org/repos/seam/modules/security/
Issue Tracking:                http://jira.jboss.org/jira/browse/SEAMSECURITY

Release Notes
=============

Version 3.0.0 Beta 1
--------------------
First beta release of Seam Security 3.x, ported from Seam 2.x to CDI.


* If using Maven, some artifacts may only be available in the JBoss Repository. To allow Seam Security to correctly function, add the JBoss Repository to Maven. Edit your ~/.m2/settings.xml, and add the following entry:

      <profile>
         <id>jboss.repository</id>
         <activation>
            <activeByDefault>true</activeByDefault>
         </activation>
         <repositories>
            <repository>
               <id>repository.jboss.org</id>
               <url>http://repository.jboss.org/maven2</url>
               <releases>
                  <enabled>true</enabled>
               </releases>
               <snapshots>
                  <enabled>false</enabled>
               </snapshots>
            </repository>
         </repositories>
      </profile>

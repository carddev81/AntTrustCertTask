INSTRUCTIONS on how to run these files in this directory
=========================================================

=========================================================
Required ANT version
		1.9.4+
=========================================================

=========================================================
Required Compiler Level
		Java 1.8
=========================================================

Current files in this directory (AntTrustCertTask/build/)
==============================================
build.buildnumber
build.email.doc.list
build.email.jccc.list
build.local.properties
build.module.list
build.properties
build.xml
==============================================

============================================================================================================
build.buildnumber
build.email.doc.list
build.email.jccc.list
build.local.properties
build.module.list
build.properties
build.xml
		These files are used to build the ant task for deployment within a developers ant home director 
		(DO NOT RUN these scripts from inside of this Working Directory. This script should be copied to your 
		local machine into a directory such as C:\build_apps for example.
============================================================================================================

============================================================================================================
ADDITIONAL INFORMATION
		More Information/Instructions about running the above scripts can be found inside of each individual
		script file listed above. PLEASE READ before running any if you are uncertain what the script is for.

Steps to build JAR file using ANT Script
1. Download and Install Ant 1.9.4.
2. Create new environment variables for ANT_HOME, JAVA_HOME and add the environment variables to PATH environment variable.
3. Copy build.xml, build.properties, build.buildnumber, build.email.doc.list, build.email.jccc.list, build.local, build.module.list, build.encryption.properties to a local builds directory.
4. Copy build.local.properties file to your C:\Users\<User _Id> folder and update the location of Java JDK and specify encrypted CVS user id and password.
5. Update build.properties file as required.
6. From the builds directory run build script using "ant" command.
7. ANT script checks out the code from CVS, does a few comparisions, complies the code and packages the code.  Ant scripts also has options to generate Java Docs and do checkstyle.
8. Script should successfully create a new JAR file in your local builds directory.
9. If the build completes successfully but fails to send email, check to make sure you have Java Mail Jar and Java Activation Framework in ANT Home / lib directory.

DISTRIBUTION NOTES
=========================================================

Current file in this directory (AntTrustCertTask\DISTRIBUTION\)
===============================================================
ant-trust-certificate-1.x.x.jar
===============================================================

==================================================================================================================
ant-trust-certificate-1.x.x.jar
		The ant-trust-certificate-1.x.jar is used for trusting secure website certificates. An example of the usage of the 
		task is below

		<typedef name="trustcertificate" classname="com.omo.free.trustcert.TrustCertTask" onerror="report"/>
		<if>
			<typefound name="trustcertificate"/>
			<then>
				<trustcertificate secureUrl="https://mysecurewebsite.isu.net" keystoreDir="./test" verbose="true" failonerror="true"/>
			</then>
			<else>
				<echo>trustcertificate task cannot be used due to Class Not Found:  com.omo.free.trustcert.TrustCertTask</echo>
			</else>
		</if>

		The example above should give you a clear understanding of how to implement this into your build.xml.  A short
		explanation of the above scripting is first the typedef task is called for setting up the trustcertificate by
		attempting to load the com.omo.free.trustcert.TrustCertTask class. After the task has been defined then you are
		able to run the trustcertificate task.
==================================================================================================================

==================================================================================================================
Parameters/Attributes
		secureUrl
			the secure url (https://host_name) that should be the trust site value. (required)

		keystoreDir
			the directory of where the local keystore will be located if not used then '.' is the location. (optional)

		verbose
			set this to true | false for verbose logging (optional)

		failonerror
			set this to true | false for failing on error during the decryption process (optional)
==================================================================================================================

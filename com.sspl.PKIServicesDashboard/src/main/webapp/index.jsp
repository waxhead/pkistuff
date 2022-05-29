<%@ page 
	language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"
    
    import="java.util.ArrayList"
    import="java.net.URI"
    import="java.net.URL"      
%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link rel="stylesheet" href="${pageContext.request.contextPath}/css/ProgressBar.css" />
<script src="${pageContext.request.contextPath}/js/progressBar.js"></script>
<title>PKI Services Dashboard</title>
</head>
<body>
<h2>PKI Services Dashboard</h2>
<p>
From here we should be able to expose a default set of checks as traffic lights to indicate key services
being available.
</p>
<p>
Additionally have some more in depth checks for ease of troubleshooting such as:
</p>
<ul>
	<li>Upload a certificate and validate it with OCSP</li>
	<li>Upload a certificate and validate it with CDP</li>
	<li>DNS check to show where OCSP is pointing</li>
	<li>Host check of server</li>
	
</ul>
<form action="CertificateValidation" method="post" enctype="multipart/form-data" >

<input type="radio" id="ocsp" name="certCheckType" value="OCSP"/>
<label for="ocsp">OCSP</label><br/>

<input type="radio" id="cdp-http" name="certCheckType" value="CDP-HTTP" />
<label for="cdp-http">CDP HTTP</label><br/>

<input type="radio" id="cdp-ldap" name="ccertCheckType" value="CDP-LDAP" />
<label for="cdp-ldap">CDP LDAP</label><br/>

<label for="certFile">Upload a valid x509 Certificate</label><br>
<input type="file" id="certFile"  name="certFile" id="certFile" /><br/>


<input type="submit" value="Submit"/>
</form>

<p>Error: ${error}</p>

<p>Certificate Details:</p>
<p>Issued to: ${issuedTo}</p>
<p>Issued by: ${certIssuer}</p>
<p>Certificate Serial Number: ${certSerialNo}</p>
<p>Not before: ${notBefore}</p>
<p>Not after: ${notAfter}</p>
<p>Number of Days Certificate is valid: ${certLenInDays}</p>
<p>Number of days since the certificate was issued: ${numberOfDaysSinceIssued}</p>
<p>Certificate life percent used: <div id="cPbar" class="progress" data-progress="1"></div>
<script>setProgress(${percentUsed},"cPbar");</script>

<p>Issued by: ${certIssuer}</p>
<p>CA Issuer Locations (AIA):</p>
<%
	URI issuerHttpURI = null;
	if(request.getAttribute("CAIssuers") == null ) {
		%><p>No Issuers found</p><%
	}
	else {
		ArrayList<URI> cai = (ArrayList<URI>) request.getAttribute("CAIssuers");
		%>
		<p>There are <%= cai.size() %> CA Issuer Locations:</p>
		<ul>
		<% 
		for( int i = 0; i < cai.size(); i++) {
			URI uri = (URI)cai.get(i);
			if( uri.isAbsolute() && uri.getScheme().equalsIgnoreCase("http")) {
				issuerHttpURI = uri;
				URL url = uri.toURL();
				%>
				<li><a href="<%= url %>"><%= url %></a></li>
				<% 
			}
			else {
				%>
				<li><%= uri.getScheme() + " " + uri.toString() %></li>
				<%
			}
		}
		%>
		</ul>
		<%
	}
%>


<p>Validation information for this certificate:</p>
<p>AIA OCSP Location: ${ocsp}</p>
<p>CRL Distribution Points (CDP):</p>
<%
	if(request.getAttribute("CDPs") == null) {
		
	}
	else {
		ArrayList<URI> cdp = (ArrayList<URI>) request.getAttribute("CDPs");
		%>
		<p>There are <%= cdp.size() %> CDP Locations:<p>
		<ul>
		<%
			for( int i = 0; i < cdp.size(); i++) {
				URI uri = (URI)cdp.get(i);
				if( uri.isAbsolute() && uri.getScheme().equalsIgnoreCase("http")) {
					URL url = uri.toURL();
					%>
					<li><a href="<%= url %>"><%= url %></a></li>
					<% 
				}
				else {
					%>
					<li><%= uri.getScheme() + " " + uri.toString() %></li>
					<%
				}
			}
		%>
		</ul>
		<%		
	}
	if( (request.getAttribute("issuerCRLHTTPRetrieved") != null) 
			&& ((boolean)request.getAttribute("issuerCRLHTTPRetrieved")) == true) {
	%>
<h2>This Certificate's CRL details: </h2>
<p>Method retrieved - HTTP</p>
<p>CRL This Update: ${issuerCRLThisUpdateHTTP}</p>
<p>CRL Next Update: ${issuerCRLNextUpdateHTTP}</p>
<p>Number of Days CRL is valid: ${crlLenInDaysHTTP}</p>
<p>Number of Days Since CRL was Issued: ${crlNumberOfDaysSinceIssuedHTTP}</p>
<p>This certificate is revoked: ${ciIsRevokedHTTP}</p>
<p>CRL life percent used: <div id="crlPbar" class="progress" data-progress="1"></div>
<script>setProgress(${crlPercentUsedHTTP}, 'crlPbar');</script>
	<%
	}
	else if( issuerHttpURI != null) {
	%>
<p>Failed to retrieve the CRL from <%= issuerHttpURI.toString()  %>.</p>	
	<%
	}
	%>

<h2>The Issuing CA details</h2>
<p>
<b>Issuer CA Name:</b>${issuserCACertName}
</p>
<p>Issued to: ${issuerIssuedTo}</p>
<p>Issued by: ${issuerCertIssuer}</p>
<p>Certificate Serial Number: ${issuerCertSerialNo}</p>
<p>Not before: ${issuerNotBefore}</p>
<p>Not after: ${issuerNotAfter}</p>
<p>Number of Days Certificate is valid: ${issuerCertLenInDays}</p>
<p>Number of days since the certificate was issued: ${issuerNumberOfDaysSinceIssued}</p>

<p>Certificate life percent used: <div id="caPbar" class="progress" data-progress="1"></div>
<script>setProgress(${ciIssuerRemaining}, 'caPbar');</script>

<p>CA Issuer Locations (AIA):</p>

<%
	if(request.getAttribute("CAIssuers") == null ) {
		%>
		<p>No Issuers found</p>
		<%
	}
	else {
		ArrayList<URI> icai = (ArrayList<URI>) request.getAttribute("issuerCAIssuers");
		%>
		<p>There are <%= icai.size() %> CA Issuer Locations:</p>
		<ul>
		<% 
		for( int i = 0; i < icai.size(); i++) {
			URI uri = (URI)icai.get(i);
			if( uri.isAbsolute() && uri.getScheme().equalsIgnoreCase("http")) {
				URL url = uri.toURL();
				%>
				<li><a href="<%= url %>"><%= url %></a></li>
				<% 
			}
			else {
				%>
				<li><%= uri.getScheme() + " " + uri.toString() %></li>
				<%
			}
		}
		%>
		</ul>
		<%
	}
%>

<p>Validation information for this certificate:</p>
<p>AIA OCSP Location: ${issuerocsp}</p>

<p>CRL Distribution Points (CDP):</p>
<%
	if(request.getAttribute("issuerCDPs") == null) {
		
	}
	else {
		ArrayList<URI> icdp = (ArrayList<URI>) request.getAttribute("issuerCDPs");
		%>
		<p>There are <%= icdp.size() %> CDP Locations:<p>
		<ul>
		<%
			for( int i = 0; i < icdp.size(); i++) {
				URI uri = (URI)icdp.get(i);
				if( uri.isAbsolute() && uri.getScheme().equalsIgnoreCase("http")) {
					URL url = uri.toURL();
					%>
					<li><a href="<%= url %>"><%= url %></a></li>
					<% 
				}
				else {
					%>
					<li><%= uri.getScheme() + " " + uri.toString() %></li>
					<%
				}
			}
		%>
		</ul>
		<%		
	}

%>

<p>Root CA Information:</p>
<h2>The Root CA details</h2>
<p>
<b>Root CA Name:</b>${rootCACertName}
</p>
<p>Issued to: ${rootIssuedTo}</p>
<p>Issued by: ${rootCertIssuer}</p>
<p>Certificate Serial Number: ${rootCertSerialNo}</p>
<p>Not before: ${rootNotBefore}</p>
<p>Not after: ${rootNotAfter}</p>
<p>Number of Days Certificate is valid: ${rootCertLenInDays}</p>
<p>Number of days since the certificate was issued: ${rootNumberOfDaysSinceIssued}</p>
<p>Certificate life percent used: <div id="rootCaPbar" class="progress" data-progress="1"></div>
<script>setProgress(${ciRootRemaining}, 'rootCaPbar');</script>


</body>
</html>
package com.sspl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.http.*;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.security.cert.X509Certificate;

public class GetIssuerCertificateHTTP {

	private URI uri;
	private byte [] cert;
	
	public GetIssuerCertificateHTTP() {
		
	}
	public GetIssuerCertificateHTTP(URI issuerURI) {
		// TODO Auto-generated constructor stub
		uri = issuerURI;
	}
	
	public byte [] getCertificateFromURI(URI uri) throws MalformedURLException, IOException {
		
		// URL getCert = uri.toURL();
		// using htis example to handle multiple redirects
		// https://stackoverflow.com/questions/1884230/httpurlconnection-doesnt-follow-redirect-from-http-to-https
		URL resourceUrl, base, next;
		Map<String, Integer> visited;
		HttpURLConnection conn;
		String location;
		int times;
		
		byte [] certByteArray = null;
		InputStream fileContent = null;
		
		visited = new HashMap<>();
		String url = uri.toString();
		while(true) {
			times = visited.compute(url, (key, count) -> count == null ? 1 : count + 1);
			System.out.println("Number of redirects so far: " + times);
			
		     if (times > 3) {
		        throw new IOException("Stuck in redirect loop");
		     }
		     
		     resourceUrl = new URL(url);
		     conn        = (HttpURLConnection) resourceUrl.openConnection();
		
		     conn.setConnectTimeout(15000);
		     conn.setReadTimeout(15000);
		     conn.setInstanceFollowRedirects(false);   // Make the logic below easier to detect redirections
		     conn.setRequestProperty("User-Agent", "Mozilla/5.0...");
		
		     switch (conn.getResponseCode())
		     {
		        case HttpURLConnection.HTTP_MOVED_PERM:
		        case HttpURLConnection.HTTP_MOVED_TEMP:
		           location = conn.getHeaderField("Location");
		           location = URLDecoder.decode(location, "UTF-8");
		           base     = new URL(url);               
		           next     = new URL(base, location);  // Deal with relative URLs
		           url      = next.toExternalForm();
		           continue;
		     }
		
		     break;
		  }
		
		try {

			fileContent = conn.getInputStream();
			//fileContent = ((URL) conn).openStream();
			// TODO This has be better handled here for redirects etc.

			int read = 0;
			final byte[] bytes = new byte[1024];
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			while ((read = fileContent.read(bytes)) != -1) {
				System.out.println("We're at: " + read);
				buffer.write(bytes, 0, read);
			}
			buffer.flush();
			certByteArray = buffer.toByteArray();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Had problem with http call: " + e.getMessage());
			e.printStackTrace();
		}
	
		return certByteArray;
		/*
		try (
		        InputStream inputStream = url.openStream(); 
		        BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream); 
		        //FileOutputStream fileOutputStream = new FileOutputStream(outputPath);
		) {
		    byte[] bucket = new byte[1024];
		    int numBytesRead;

		    while ((numBytesRead = bufferedInputStream.read(bucket, 0, bucket.length)) != -1) {
		        fileOutputStream.write(bucket, 0, numBytesRead);
		    }
		}
		*/
		
		//.proxy(ProxySelector.of(new InetSocketAddress("www-proxy.com", 8080)))

		/*
		 * https://openjdk.java.net/groups/net/httpclient/intro.html
		 * https://openjdk.java.net/groups/net/httpclient/recipes.html
		 * 
		 */
		
		/*
		System.out.println("getCertifcateFromURI:" + uri.toString());
		
		HttpClient client = HttpClient.newBuilder()
				.version(Version.HTTP_2)
				.followRedirects(Redirect.ALWAYS)
				.authenticator(Authenticator.getDefault())
				.build();

		HttpRequest request = HttpRequest.newBuilder()
				.uri(uri)
				.timeout(Duration.ofMinutes(1))
				.build();
					  
		HttpResponse<InputStream> response;
		byte [] certByteArray;
		try {
			response = client.send(request, BodyHandlers.ofInputStream());
			System.out.println("Response Code: " + response.statusCode());

			int read = 0;
			final byte[] bytes = new byte[1024];
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			
			while((read = response.body().read(bytes)) != -1) {
				System.out.println("We're at: " + read);
				buffer.write(bytes,0,read);
			}
			buffer.flush();
			certByteArray = buffer.toByteArray();
			
			if(certByteArray == null ) {
				System.out.println("No file was provided in the http call...");
			}
			
		} catch (IOException | InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return certByteArray;
		*/
	}

}

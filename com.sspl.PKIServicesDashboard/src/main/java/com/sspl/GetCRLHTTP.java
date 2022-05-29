package com.sspl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import javax.print.DocFlavor.URL;


public class GetCRLHTTP {

	private URI uri;
	/***
	 * This just gets the CRL from the http CDP.
	 * 
	 * Not sure what to return yet, probably should return a CRL object.
	 */
	public GetCRLHTTP(URI crlURI) {
		// TODO Auto-generated constructor stub
		uri =crlURI;
	}
	
	
	// This is duplicating code and could be done with more generic helper class and code
	public byte []  getCRLfromURL () throws MalformedURLException {
		
		
		URL getCRL = uri.toURL();
		
		byte [] crlByteArray  = null;
		InputStream fileContent = null;
		try {
			fileContent = getCRL.openStream();
			// TODO This has be better handled here for redirects etc.
			
			int read = 0;
			final byte[] bytes = new byte[1024];
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			while ((read = fileContent.read(bytes)) != -1) {
				System.out.println("We're at: " + read);
				buffer.write(bytes, 0, read);
			}
			buffer.flush();
			crlByteArray = buffer.toByteArray();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Had problem with http call: " + e.getMessage());
			e.printStackTrace();
		}
		
		return crlByteArray;
	}
	
	

}

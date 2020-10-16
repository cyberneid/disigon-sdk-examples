package com.cyberneid.disigon.sdk.examples;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import com.cyberneid.disigon.sdk.CertReference;
import com.cyberneid.disigon.sdk.CertSelector;
import com.cyberneid.disigon.sdk.SignatureException;
import com.qequipe.p11.Certificate;
import com.qequipe.p11.P11Attribute;
import com.qequipe.p11.P11Exception;
import com.qequipe.p11.P11Object;
import com.qequipe.p11.P11ObjectCollection;
import com.qequipe.p11.P11Session;
import com.qequipe.p11.X509Certificate;

public class AWSHSMCertSelector implements CertSelector {

	private String privateKeyId;
	private String certificatePath;
	/**
	 * Initializes a new instance of the ByLabelCertSelector class by specifing selection criteria.
	 * @param label is the label of the requested certificate
	 */
	public AWSHSMCertSelector(String privateKeyId, String certificatePath)
	{
		this.privateKeyId = privateKeyId;
		this.certificatePath = certificatePath;
	}
	

	/* Selects the certificate based on the implemented criteria
	 * @see P11Session
	 */
	@Override
	public CertReference select(final Object session) throws SignatureException
	{		
		
		try
		{
			FileInputStream fins = new FileInputStream(certificatePath);
			ByteArrayOutputStream bouts = new ByteArrayOutputStream();
			copy(fins, bouts);
			fins.close();
			
			CertReference certinfo = new CertReference();
			
			 certinfo.id = privateKeyId;
	         certinfo.rawValue = bouts.toByteArray();
	         
	         if(((P11Session)session).isLoggedIn())
	         {
	        	 ArrayList<P11Attribute> attrs = new ArrayList<P11Attribute>();
	        	 
				 attrs.add(new P11Attribute(P11Attribute.CKA_CLASS, P11Object.CKO_PRIVATE_KEY));				
				 attrs.add(new P11Attribute(P11Attribute.CKA_ID, privateKeyId));

				 P11ObjectCollection objects = ((P11Session)session).getObjects();
				 
				 List<P11Object> prikeys = objects.find(attrs, 1);

				 if(prikeys.size() > 0)
				 {
					 certinfo.privKeyRef = prikeys.get(0);
				 }
	         }
	         
	         return certinfo;
		}
		catch (P11Exception ex)
		{
			ex.printStackTrace();
			throw new SignatureException(ex.getCKR(), ex.getMessage());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
			throw new SignatureException(SignatureException.ERROR_CERTIFICATE_NOT_FOUND);
		}
	}
	
	private static void copy(InputStream from, OutputStream to) throws IOException
    {
        byte[] buffer = new byte[8192];
        int bytesRead;

        while ((bytesRead = from.read(buffer)) != -1)
            to.write(buffer, 0, bytesRead); // write            
    }

}

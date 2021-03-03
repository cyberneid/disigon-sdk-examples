package com.cyberneid.disigon.sdk.examples;

import java.io.File;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.List;

import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x500.style.IETFUtils;
import org.spongycastle.cert.X509CertificateHolder;

import com.cyberneid.disigon.sdk.Disigon;
import com.cyberneid.disigon.sdk.P7MDocument;
import com.cyberneid.disigon.sdk.SignatureVerifier;
import com.cyberneid.disigon.sdk.SignerInfo;
import com.cyberneid.disigon.sdk.TimeStampInfo;

/**
 *  @author UgoChirico
 *  https://www.ugochirico.com
 *  https://www.cyberneid.com
 */
public class SignatureVerification {

	static boolean CERTIFICATE_BY_PATH = true;
	
	public static void main(String args[])
    {    	
    	// the input file
		String input = "Lorem Ipsum.pdf.p7m";
				
		System.out.println("DISIGON version: " + Disigon.VERSION);
		
		// set licensee and product key
		// contact us at https://www.cyberneid.com to get a lincese key
		Disigon.setLicense("<licensee>", "<productkey>");
		
		
		try
		{
			SignatureVerifier verifier = SignatureVerifier.createSignatureVerifier(new File(input));
			
			// number of signature in the file
			int signatureCount = verifier.getNumberOfSignatures();
			System.out.println("signatures: " + signatureCount);
			
			// has timestamp
			boolean hasTimestamp = verifier.hasTimeStamp();
			System.out.println("hasTimestamp: " + hasTimestamp);
			
			// List of internal signatures as SignerInfo object
			List<SignerInfo> signerInfoList = verifier.getSignatures();
			
			
			for(SignerInfo signerInfo : signerInfoList)
			{
          
	            // read the signer from certificate	           

	            try
	            {
	            	X509Certificate certificate = signerInfo.getSignerCertificate();

	                X509CertificateHolder cert = new X509CertificateHolder(certificate.getEncoded());
	                
	                // subject
	                X500Name dn = cert.getSubject();
	                try 
	                {
	                    RDN dnCN = dn.getRDNs(BCStyle.CN)[0];	
	                    String cn = IETFUtils.valueToString(dnCN.getFirst().getValue());
	        			System.out.println("CN: " + cn);
	                }
	                catch(Exception ex)
	                {
	                    ex.printStackTrace();
	                }

	                
	                // Issuer
	                // read authority from certificate
	                String authority = getIssuer(certificate);
	                System.out.println("CA cert: " + authority);
	                
	                // check timestamp
	                if(signerInfo.hasTimeStampToken())
	                {
		                SimpleDateFormat sd = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

	                    TimeStampInfo tsi = signerInfo.getTimeStampInfo();
	                    System.out.println("Marca temporale: " + sd.format(tsi.getTime()));
	
	                    try
	                    {
	                    	System.out.println("TSA: " + tsi.getTSAName());
	                    }
	                    catch (Exception ex)
	                    {
	                        ex.printStackTrace();
	                    }
	                }
	                
	                // verify the signature
                    int bitmask = signerInfo.verify();

                    String sigType;
                    if ((bitmask & P7MDocument.VERIFIED_SIGNED_ATTRIBUTE_CT) != 0 &&
                            (bitmask & P7MDocument.VERIFIED_SIGNED_ATTRIBUTE_MD) != 0 &&
                            (bitmask & P7MDocument.VERIFIED_SIGNED_ATTRIBUTE_SC) != 0)
                    {
                    	sigType = "CAdES-BES";
                    }
                    else
                    {
                        sigType = "PKCS#7";
                    }
            
                    System.out.println("Signature: " + sigType);

                    // check the signature validity
                    if ((bitmask & P7MDocument.VERIFIED_SIGNATURE) != 0)
                    {
                    	System.out.println("signature ok");
                    }
                    else
                    {
                    	System.out.println("signature nok");
                    }

                    if ((bitmask & P7MDocument.VERIFIED_CERT_VALIDITY) != 0)
                    {
                        if ((bitmask & P7MDocument.VERIFIED_CERTIFICATE_CHAIN) != 0)
                        {
                        	System.out.println("certificate ok");
                        }
                        else
                        {
                        	System.out.println("certificate not trusted");
                        }
                    }
                    else
                    {
                    	System.out.println("certificate expired");
                    }

                    if ((bitmask & P7MDocument.VERIFIED_CRL_LOADED) != 0)
                    {
                        if ((bitmask & P7MDocument.VERIFIED_CRL) != 0)
                        {
                        	System.out.println("revocation status ok");
                        }
                        else if ((bitmask & P7MDocument.VERIFIED_CRL_REVOKED) != 0)
                        {
                        	System.out.println("revocation status revoked");
                        }
                        else if ((bitmask & P7MDocument.VERIFIED_CRL_SUSPENDED) != 0)
                        {
                        	System.out.println("revocation status suspended");
                        }
                    }
                    else
                    {
                    	System.out.println("revocation status unknown");
                    }
	            } 
	            catch (Exception ex)
	            {
	            	ex.printStackTrace();
                
                };
            }
			
			System.out.println("done");
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		} 
    }
	
	public static String getIssuer(X509Certificate certificate) {
        String issuerStr = "";
        if (certificate != null) {
            issuerStr = certificate.getIssuerDN().toString();
        }
        return issuerStr;
    }

    public static String getSubject(X509Certificate certificate) {
        String subjectStr = "";
        if (certificate != null) {
            subjectStr = certificate.getSubjectDN().toString();
        }
        return subjectStr;
    }
}

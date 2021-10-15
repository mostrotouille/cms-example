package mx.com.mostrotuille.example.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.apache.commons.ssl.PKCS8Key;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CmsApplication {
	public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
		final CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

		final Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();

		final KeyTransRecipientInformation recipientInformation = (KeyTransRecipientInformation) recipients.iterator()
				.next();

		return recipientInformation.getContent(new JceKeyTransEnvelopedRecipient(privateKey));
	}

	public static byte[] encrypt(byte[] data, X509Certificate x509Certificate) throws Exception {
		final CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
		cmsEnvelopedDataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509Certificate));

		final OutputEncryptor outputEncryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

		final CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(new CMSProcessableByteArray(data),
				outputEncryptor);

		return cmsEnvelopedData.getEncoded();
	}

	public static KeyStore getKeystore(InputStream keyStoreInputStream, String keyStorePassword) throws Exception {
		final KeyStore result = KeyStore.getInstance("jks");
		result.load(keyStoreInputStream, keyStorePassword.toCharArray());

		return result;
	}

	public static PrivateKey getPrivateKey(InputStream privateKeyInputStream, String password) throws Exception {
		final PKCS8Key pkcs8Key = new PKCS8Key(privateKeyInputStream, password.toCharArray());

		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(pkcs8Key.getDecryptedBytes());

		return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
	}

	public static PrivateKey getPrivateKey(KeyStore keyStore, String alias, String password) throws Exception {
		return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
	}

	public static X509Certificate getX509Certificate(InputStream certificateInputStream) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certificateInputStream);
	}

	public static void main(final String[] ar) {
		try {
			Security.addProvider(new BouncyCastleProvider());

			final ClassLoader classLoader = CmsApplication.class.getClassLoader();

			final KeyStore keyStore = getKeystore(classLoader.getResourceAsStream("keystore.jks"), "mystorepassword");

			final String message = "Hello, world!";

			System.out.println("Data:\n" + message);

			byte[] signedData = sign(message.getBytes(),
					getX509Certificate(classLoader.getResourceAsStream("remitent.cer")),
					getPrivateKey(keyStore, "remitent_key", "remitentpassword"));

			byte[] encryptedData = encrypt(signedData,
					getX509Certificate(classLoader.getResourceAsStream("destinatary.cer")));

			final String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);

			System.out.println("\nEncrypted data (base 64):\n" + encryptedDataBase64);

			byte[] decryptedData = decrypt(Base64.getDecoder().decode(encryptedDataBase64),
					getPrivateKey(keyStore, "destinatary_key", "destinatarypassword"));

			if (verifySign(decryptedData)) {
				byte[] data = unsign(decryptedData);

				System.out.println("\nDecrypted data:\n" + new String(data));
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static byte[] sign(byte[] data, X509Certificate x509Certificate, PrivateKey privateKey) throws Exception {
		final List<X509Certificate> x509CertificateList = new ArrayList<X509Certificate>();
		x509CertificateList.add(x509Certificate);

		final CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
		cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
						.build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey), x509Certificate));
		cmsGenerator.addCertificates(new JcaCertStore(x509CertificateList));

		final CMSSignedData cmsSignedData = cmsGenerator.generate(new CMSProcessableByteArray(data), true);

		return cmsSignedData.getEncoded();
	}

	public static byte[] unsign(byte[] decryptedData) throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		final CMSSignedData cmsSignedData = new CMSSignedData(decryptedData);
		cmsSignedData.getSignedContent().write(outputStream);

		return outputStream.toByteArray();
	}

	@SuppressWarnings("unchecked")
	public static boolean verifySign(byte[] signedData) throws Exception {
		ByteArrayInputStream inputStream = null;
		ASN1InputStream asn1InputStream = null;

		try {
			inputStream = new ByteArrayInputStream(signedData);
			asn1InputStream = new ASN1InputStream(inputStream);

			final CMSSignedData cmsSignedData = new CMSSignedData(
					ContentInfo.getInstance(asn1InputStream.readObject()));

			final Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();

			final SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();

			final Collection<SignerInformation> signers = signerInformationStore.getSigners();

			final SignerInformation signer = signers.iterator().next();

			final X509CertificateHolder x509CertificateHolder = ((Collection<X509CertificateHolder>) certificates
					.getMatches(signer.getSID())).iterator().next();

			return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(x509CertificateHolder));
		} catch (Exception ex) {
			throw ex;
		} finally {
			if (asn1InputStream != null) {
				try {
					asn1InputStream.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
}
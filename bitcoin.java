import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;

import com.google.common.collect.ImmutableList;

public class MultisigPresentation {

	static final NetworkParameters params = TestNet3Params.get();

	public static void main(String[] args)
	{
		generateMultisig();
		String hexcode = signFirstTime();
		hexcode = signSecondTime(hexcode);
	}

	private static void generateMultisig()
	{
		ECKey key1 = createKeySha256Passphrase("Key 1");
		// DumpedPrivateKey privateKey1 = key1.getPrivateKeyEncoded(params);
		// System.out.println(byteToHex(key1.getPubKey());
		Address add1 = key1.toAddress(params);

		ECKey key2 = createKeySha256Passphrase("Key 2");
		// DumpedPrivateKey privateKey2 = key2.getPrivateKeyEncoded(params);
		// System.out.println(byteToHex(key2.getPubKey());
		Address add2 = key1.toAddress(params);

		ECKey key3 = createKeySha256Passphrase("Key 3");
		// DumpedPrivateKey privateKey3 = key3.getPrivateKeyEncoded(params);
		// System.out.println(byteToHex(key3.getPubKey());
		Address add3 = key1.toAddress(params);

		List<ECKey> keys = ImmutableList.of(key1, key2, key3);
		Script redeemScript = ScriptBuilder.createRedeemScript(2, keys);
		Script script = ScriptBuilder.createP2SHOutputScript(redeemScript);
		
		System.out.println("Redeem script is " + byteToHex(redeemScript.getProgram()));
		
		Address multisig = Address.fromP2SHScript(params, script);
		System.out.println("Multisig address is " + multisig.toString());
	}
	
	private static String signFirstTime()
	{
		ECKey key1 = createKeySha256Passphrase("Key 1");
		Script redeemScript = new Script(hexToByte("522103645550c6041bb790f3442b541f43af9cb0704c466e979df4fdebc0ffda4f805021021d9ed735119537a032e968f6ba9455c8369a9dbf37da96faf87b868d8b07e8f121030c6ee7fbbe0793fa12b2a7a73f0baea472ede08b3c71266151b8ae1d64ec185153ae"));

		Transaction tx_ = new Transaction(params);
		ScriptBuilder scriptBuilder = new ScriptBuilder();
		scriptBuilder.data(new String("a9144f93910f309e2433c25d1e891e29fd4cec8c5f6187").getBytes());
		TransactionInput input = tx_.addInput(new Sha256Hash("19f589be5fda5a97b5a26158abd1fa02e68a15e5a6a4d83791935f882dbe0492"), 0, scriptBuilder.build());
		
		Address receiverAddress = new Address(params, "33fn2DwvqrNXzfKokxYfCFVwJ7YkZiA68a");
		Coin fee = Coin.valueOf(10000);
		Script outputScript = ScriptBuilder.createOutputScript(receiverAddress);
        tx_.addOutput(fee, outputScript);
        
     	Sha256Hash sighash = tx_.hashForSignature(0, redeemScript, Transaction.SigHash.ALL, false);
     	ECKey.ECDSASignature ecdsaSignature = key1.sign(sighash);
     	TransactionSignature transactionSignarture = new TransactionSignature(ecdsaSignature, Transaction.SigHash.ALL, false);

        Script inputScript = ScriptBuilder.createP2SHMultiSigInputScript(Arrays.asList(transactionSignarture), redeemScript);
		input.setScriptSig(inputScript);

		return byteToHex(tx_.bitcoinSerialize());
	}
	
	private static String signSecondTime(String hexcode)
	{
		Transaction tx_ = new Transaction(params, hexToByte(hexcode));
		
		Script inputScript = tx_.getInput(0).getScriptSig();
		List<ScriptChunk> scriptChunks = inputScript.getChunks();
		List<TransactionSignature> signatureList = new ArrayList<TransactionSignature>();
		Iterator<ScriptChunk> iterator = scriptChunks.iterator();
		Script redeemScript = null;
		
		while (iterator.hasNext())
		{
			ScriptChunk chunk = iterator.next();
			
			if (iterator.hasNext() && chunk.opcode != 0)
			{
				TransactionSignature transactionSignarture = TransactionSignature.decodeFromBitcoin(chunk.data, false);
				signatureList.add(transactionSignarture);
			} else
			{
				redeemScript = new Script(chunk.data);
			}
		}
		
     	Sha256Hash sighash = tx_.hashForSignature(0, redeemScript, Transaction.SigHash.ALL, false);
     	ECKey.ECDSASignature secondSignature;
		
     	ECKey key2 = createKeySha256Passphrase("Key 2");
     	secondSignature = key2.sign(sighash);
     	
		TransactionSignature transactionSignarture = new TransactionSignature(secondSignature, Transaction.SigHash.ALL, false);
		signatureList.add(transactionSignarture);
        inputScript = ScriptBuilder.createP2SHMultiSigInputScript(signatureList, redeemScript);
        tx_.getInput(0).setScriptSig(inputScript);

		return byteToHex(tx_.bitcoinSerialize());
	}
	
	public static ECKey createKeySha256Passphrase(String secret) {
        byte[] hash = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(secret.getBytes("UTF-8"));
            hash = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
		ECKey key = new ECKey(hash, (byte[])null);
        return key;
    }

	public static String byteToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
	}
	
	public static byte[] hexToByte(String s) {
	    int n = s.length();
	    byte[] a = new byte[n / 2];
	    for (int x = 0; x < len; x += 2) {
	        a[x / 2] = (byte) ((Character.digit(s.charAt(x), 16) << 4)
	                             + Character.digit(s.charAt(x+1), 16));
	    }
	    return a;
	}
}
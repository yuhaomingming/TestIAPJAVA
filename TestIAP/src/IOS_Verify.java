

import java.io.BufferedOutputStream;  
import java.io.BufferedReader;  
import java.io.InputStream;  
import java.io.InputStreamReader;  
import java.net.URL;  
import java.security.MessageDigest;  
import java.security.cert.CertificateException;  
import java.security.cert.X509Certificate;  
import java.util.HashMap;
import java.util.Locale;  

import java.util.Map;
import javax.net.ssl.HostnameVerifier;  
import javax.net.ssl.HttpsURLConnection;  
import javax.net.ssl.SSLContext;  
import javax.net.ssl.SSLSession;  
import javax.net.ssl.TrustManager;  
import javax.net.ssl.X509TrustManager;  

import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;
 
 
  

  
  
  
  
public class IOS_Verify {
	public static void main(String[] args) {
		
		String receipt= "{\"signature\" = \"AiWDDxr1l5g0LTE/8Q/OYiaUBQYX7XmiMxn7+x41p3EhEosl8PMh3ZUhLVlmoRBxFk+Aaedl+/5NVsYAtQH9zbvXdgqM4XhUWmnnVxwm0a4iM66X5Y6PT0vIG4i7qDT9YzXIkUzMtIf2xdL4iMDYgxl4nqONdZf5uI2sQx7ZzAr0AAADVzCCA1MwggI7oAMCAQICCGUUkU3ZWAS1MA0GCSqGSIb3DQEBBQUAMH8xCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEzMDEGA1UEAwwqQXBwbGUgaVR1bmVzIFN0b3JlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA5MDYxNTIyMDU1NloXDTE0MDYxNDIyMDU1NlowZDEjMCEGA1UEAwwaUHVyY2hhc2VSZWNlaXB0Q2VydGlmaWNhdGUxGzAZBgNVBAsMEkFwcGxlIGlUdW5lcyBTdG9yZTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMrRjF2ct4IrSdiTChaI0g8pwv/cmHs8p/RwV/rt/91XKVhNl4XIBimKjQQNfgHsDs6yju++DrKJE7uKsphMddKYfFE5rGXsAdBEjBwRIxexTevx3HLEFGAt1moKx509dhxtiIdDgJv2YaVs49B0uJvNdy6SMqNNLHsDLzDS9oZHAgMBAAGjcjBwMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUNh3o4p2C0gEYtTJrDtdDC5FYQzowDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBSpg4PyGUjFPhJXCBTMzaN+mV8k9TAQBgoqhkiG92NkBgUBBAIFADANBgkqhkiG9w0BAQUFAAOCAQEAEaSbPjtmN4C/IB3QEpK32RxacCDXdVXAeVReS5FaZxc+t88pQP93BiAxvdW/3eTSMGY5FbeAYL3etqP5gm8wrFojX0ikyVRStQ+/AQ0KEjtqB07kLs9QUe8czR8UGfdM1EumV/UgvDd4NwNYxLQMg4WTQfgkQQVy8GXZwVHgbE/UC6Y7053pGXBk51NPM3woxhd3gSRLvXj+loHsStcTEqe9pBDpmG5+sk4tw+GK3GMeEN5/+e1QT9np/Kl1nj+aBw7C0xsy0bFnaAd1cSS6xdory/CUvM6gtKsmnOOdqTesbp0bs8sn6Wqs0C9dgcxRHuOMZ2tm8npLUm7argOSzQ==\";\"purchase-info\" = \"ewoJIm9yaWdpbmFsLXB1cmNoYXNlLWRhdGUtcHN0IiA9ICIyMDE0LTA0LTA2IDE4OjQ1OjU4IEFtZXJpY2EvTG9zX0FuZ2VsZXMiOwoJInVuaXF1ZS1pZGVudGlmaWVyIiA9ICI0OWVkYTI5ZTBhN2RhZjQ1MTRhZTA2NGI5ZTA3N2Q0ZmRhYjVmMTljIjsKCSJvcmlnaW5hbC10cmFuc2FjdGlvbi1pZCIgPSAiMTAwMDAwMDEwNjg1NTg4NyI7CgkiYnZycyIgPSAiMS4wLjAiOwoJInRyYW5zYWN0aW9uLWlkIiA9ICIxMDAwMDAwMTA2ODU1ODg3IjsKCSJxdWFudGl0eSIgPSAiMSI7Cgkib3JpZ2luYWwtcHVyY2hhc2UtZGF0ZS1tcyIgPSAiMTM5NjgzNTE1ODU3OCI7CgkidW5pcXVlLXZlbmRvci1pZGVudGlmaWVyIiA9ICJGMjMxRUVCQi0zMDVGLTQyMjctQUM3QS04MzZCQkNBMDQ5RTgiOwoJInByb2R1Y3QtaWQiID0gImRxeF81MDAiOwoJIml0ZW0taWQiID0gIjc5OTE3NjQ0OCI7CgkiYmlkIiA9ICJjb20uZ2Zhbi5nYW1lLmRxeCI7CgkicHVyY2hhc2UtZGF0ZS1tcyIgPSAiMTM5NjgzNTE1ODU3OCI7CgkicHVyY2hhc2UtZGF0ZSIgPSAiMjAxNC0wNC0wNyAwMTo0NTo1OCBFdGMvR01UIjsKCSJwdXJjaGFzZS1kYXRlLXBzdCIgPSAiMjAxNC0wNC0wNiAxODo0NTo1OCBBbWVyaWNhL0xvc19BbmdlbGVzIjsKCSJvcmlnaW5hbC1wdXJjaGFzZS1kYXRlIiA9ICIyMDE0LTA0LTA3IDAxOjQ1OjU4IEV0Yy9HTVQiOwp9\";\"environment\" = \"Sandbox\";\"pod\" = \"100\";\"signing-status\" = \"0\";}";		
		System.out.println("Map:"+checkorder(receipt));
	}
	
	public static Map<String, String> checkorder(String receipt){
		Map<String, String> map=new HashMap<String, String>();
		map.put("receipt", receipt);
		try {
			if(receipt!=null){
				String type=getEnvironment(receipt);
				map.put("type", type);
				String result=buyAppVerify(receipt,type);
				if(result!=null){
					map.put("result", result);
					JSONObject job=new JSONObject(result);
					if(job.has("status")&&0==job.getInt("status")){
							if(job.has("receipt")){
								job = job.getJSONObject("receipt");
								if(job.has("product_id")&&job.has("product_id")){
									map.put("status", "0");
									map.put("product_id", job.getString("product_id"));
									map.put("transaction_id", job.getString("transaction_id"));
								}							
							}
					}
				}
				
			}
		} catch (JSONException e) {
			e.printStackTrace();
		}
		if(!map.containsKey("status")){
			map.put("status", "-1");
		}
		return map;
	}
	
    private static class TrustAnyTrustManager implements X509TrustManager {  
          
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {  
        }  
      
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {  
        }  
      
        public X509Certificate[] getAcceptedIssuers() {  
            return new X509Certificate[]{};  
        }  
    }  
      
    private static class TrustAnyHostnameVerifier implements HostnameVerifier {  
        public boolean verify(String hostname, SSLSession session) {  
            return true;  
        }  
    }  
    private static final String url_sandbox="https://sandbox.itunes.apple.com/verifyReceipt";  
    private static final String url_verify="https://buy.itunes.apple.com/verifyReceipt";  
      
      
    /** 
     * 苹果服务器验证 
     * @param receipt 账单 
     * @url 要验证的地址 
     * @return null 或返回结果 
     * 沙盒   https://sandbox.itunes.apple.com/verifyReceipt 
     *  
     */  
    public static String buyAppVerify(String receipt,String verifyState)  
    {  
       String url=url_verify;  
       if(verifyState!=null&&verifyState.equals("Sandbox")){  
           url=url_sandbox;  
       }  
       String buyCode=getBASE64(receipt);  
       try{  
           SSLContext sc = SSLContext.getInstance("SSL");  
           sc.init(null, new TrustManager[]{new TrustAnyTrustManager()}, new java.security.SecureRandom());  
           URL console = new URL(url);  
           HttpsURLConnection conn = (HttpsURLConnection) console.openConnection();  
           conn.setSSLSocketFactory(sc.getSocketFactory());  
           conn.setHostnameVerifier(new TrustAnyHostnameVerifier());  
           conn.setRequestMethod("POST");  
           conn.setRequestProperty("content-type", "text/json");  
           conn.setRequestProperty("Proxy-Connection", "Keep-Alive");  
           conn.setDoInput(true);  
           conn.setDoOutput(true);  
           BufferedOutputStream hurlBufOus=new BufferedOutputStream(conn.getOutputStream());  
             
           String str= String.format(Locale.CHINA,"{\"receipt-data\":\"" + buyCode+"\"}");  
           hurlBufOus.write(str.getBytes());  
           hurlBufOus.flush();  
                     
            InputStream is = conn.getInputStream();  
            BufferedReader reader=new BufferedReader(new InputStreamReader(is));  
            String line = null;  
            StringBuffer sb = new StringBuffer();  
            while((line = reader.readLine()) != null){  
              sb.append(line);  
            }  
  
            return sb.toString();  
       }catch(Exception ex)  
       {  
           ex.printStackTrace();  
       }  
       return null;  
    }  
      
    /** 
     * 根据原始收据返回苹果的验证地址: 
     *  * 沙箱    https://sandbox.itunes.apple.com/verifyReceipt 
     * 真正的地址   https://buy.itunes.apple.com/verifyReceipt 
     * @param receipt 
     * @return Sandbox 测试单   Real 正式单 
     */  
    public static String getEnvironment(String receipt)  
    {  
        try{  
        	JSONObject job=new JSONObject(receipt);
            if(job.has("environment")){  
                String evvironment=job.getString("environment");  
                return evvironment;  
            }  
        }catch(Exception ex){  
            ex.printStackTrace();  
        }  
        return "Real";  
    }  
     
    /** 
     * 用BASE64加密 
     * @param str 
     * @return 
     */  
    public static String getBASE64(String str) {  
    	Base64.encodeBase64(str.getBytes());
    	byte[] b = Base64.encodeBase64(str.getBytes()); 
        String s = new String(b);  
        return s;  
    }  
  
    /** 
     * 解密BASE64字窜 
     * @param s 
     * @return 
     */  
    public static String getFromBASE64(String str) {  
    	
        byte[] b = Base64.decodeBase64(str.getBytes()); 
        String s = new String(b); 
        return s;  
    }  
      
    /** 
    * md5加密方法 
    * @author: zhengsunlei 
    * Jul 30, 2010 4:38:28 PM 
    * @param plainText 加密字符串 
    * @return String 返回32位md5加密字符串(16位加密取substring(8,24)) 
    * 每位工程师都有保持代码优雅的义务 
    * each engineer has a duty to keep the code elegant 
    */  
    public final static String md5(String plainText) {  
       // 返回字符串  
       String md5Str = null;  
       try {  
        // 操作字符串  
        StringBuffer buf = new StringBuffer();  
       /** 
        * MessageDigest 类为应用程序提供信息摘要算法的功能，如 MD5 或 SHA 算法。 
        * 信息摘要是安全的单向哈希函数，它接收任意大小的数据，并输出固定长度的哈希值。 
        *  
        * MessageDigest 对象开始被初始化。 
        * 该对象通过使用 update()方法处理数据。 
        * 任何时候都可以调用 reset()方法重置摘要。 
        * 一旦所有需要更新的数据都已经被更新了，应该调用digest()方法之一完成哈希计算。  
        *  
        * 对于给定数量的更新数据，digest 方法只能被调用一次。 
        * 在调用 digest 之后，MessageDigest 对象被重新设置成其初始状态。 
        */   
        MessageDigest md = MessageDigest.getInstance("MD5");  
         
        // 添加要进行计算摘要的信息,使用 plainText 的 byte 数组更新摘要。  
        md.update(plainText.getBytes());  
        // 计算出摘要,完成哈希计算。  
        byte b[] = md.digest();  
        int i;  
        for (int offset = 0; offset < b.length; offset++) {  
         i = b[offset];  
         if (i < 0) {  
          i += 256;  
         }  
         if (i < 16) {  
          buf.append("0");  
         }  
         // 将整型 十进制 i 转换为16位，用十六进制参数表示的无符号整数值的字符串表示形式。  
         buf.append(Integer.toHexString(i));  
        }  
        // 32位的加密  
        md5Str = buf.toString();  
        // 16位的加密  
        // md5Str = buf.toString().md5Strstring(8,24);  
       } catch (Exception e) {  
        e.printStackTrace();  
       }  
       return md5Str;  
    }  
      
}  
package org.tain;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

import SK.Utility.UCPIDResponse;

public class Test {

	public static void main(String[] args) {

		String person_encoded = "마이데이터 사업자로부터 넘어온 signed_personInfoReq url-safe encoding 된 값";
		String consent_encode = "마이데이터 사업자로부터 넘어온 signed_consentInfo url-safe encoding 된 값";
		
		//1. url-safe decoding
		byte[] signed_personInfoReq = VarUtils.base64_url_decoding(person_encoded);
		byte[] signed_consentInfo = VarUtils.base64_url_decoding(consent_encode);

		//2. 검증 데몬(혹은 검증라이브러리)에 넣기 위한 포맷의 서명 데이터 획득
		String personInfoForVerify = VarUtils.get_data_for_CMSVerify(person_encoded);
		String consentInfoForVerify = VarUtils.get_data_for_CMSVerify(consent_encode);
		
		//3. 각 서명 데이터에서 인증서 byte 값 획득
		byte[] personCert = ClientUtils.get_certificate_from_cms(signed_personInfoReq);
		byte[] consentCert = ClientUtils.get_certificate_from_cms(signed_consentInfo);
		
		//4. 각 서명 데이터에서 nonce값 획득
		String ucpidNonceInCms = ClientUtils.get_ucpidNonce_from_signedPersonInfoReq(signed_personInfoReq);
		String consentNonceInCms = ClientUtils.get_consentNonce_from_signdConsentInfo(signed_consentInfo);
		String ucpidNonceInApi = "마이데이터 사업자로부터 api-002를 통해 전달 받은 ucpidNonce 값";
		String consentNonceInApi = "마이데이터 사업자로부터 api-002를 통해 전달 받은 consentNonce 값";
		
		if(ucpidNonceInCms.equals(ucpidNonceInApi) && consentNonceInCms.equals(consentNonceInApi)){//nonce 값이 동일할 경우 (재전송공격 방지)
			if(isSameCertificate(personCert,consentCert)){ // byte 배열이 동일한 지 확인하는 함수 정보제공자가 개발 필요 
				/*
				 * 위의 personInfoForVerify, consentInfoForVerify 값을 검증데몬 혹은 검증라이브러리에 파라미터값으로 넣어 서명 검증 및 인증서 유효성 검증 실시. 
				 */
				if(isVerifyingOk()){ //검증이 정상적으로 완료되었을 경우
					//properties 파일 위치 설정. (절대경로 혹은 상대 경로 모두 가능)
					VarUtils.setPropertiesPath("config_data/route.properties");
					
					String ucpIdNonce = "정보제공자가 직접 생성한 ucpIdNonce 값";
					String cpCode = "정보제공자 기관코드 ";
					String cpRequestNumber = "마이데이터사업자로부터 받은 tx_id 값";
					String ca_code = "마이데이터사업자로부터 받은 인증기관 기관코드";
					String signCertPath = VarUtils.getResourceFromProperty("signCert");
					byte[] certificate = VarUtils.getFromFile(signCertPath);
					
					if("SignKorea".equals(ca_code)){						
						String serverIp = "211.175.81.101"; //koscom ucpid test server ip
						int serverPort = 8098; //koscom ucpid test server port
						/**
						 * signedAttirbute 존재 > flag : 1
						 * signedAttribute 존재 x > flag : 0 
						 */
						byte[] UCPIDRequest = RequestUtils.getUCPIDRequest(ucpIdNonce, cpCode, cpRequestNumber, certificate, signed_personInfoReq, 1);
						System.out.println("request to ucpid server is started.");
						byte[] bUCPIDResponse = request2UCPID(UCPIDRequest, serverIp, serverPort);
						System.out.println("request to ucpid server is successfully done.");
						
						/**
						 * get ucpidResponse's status
						 * status가 OK일 경우에만 ucpidResponse의 모든 데이터가 정상적으로 존재
						 */
						String status = ResponseUtils.getStatusCode(bUCPIDResponse); 
						
						if(StatusUtils.isOk(status)){
							UCPIDResponse ucpidResponse = ResponseUtils.getInstance(bUCPIDResponse);
							
							int version = ucpidResponse.getVersion();
							String UCPIDNonce = ucpidResponse.getUcpidNonce();
							String CpRequestNumber = ucpidResponse.getCpRequestNumber();
							String certDn = ucpidResponse.getCertDn();
							String CpCode = ucpidResponse.getCpCode();
							String di = ucpidResponse.getDi();
							String realName = ucpidResponse.getRealName();
							int gender = ucpidResponse.getGender();
							int nationalInfo = ucpidResponse.getNationalInfo();
							String birthDate = ucpidResponse.getBirthDate();
							int ciupdate = ucpidResponse.getCiUpdate();
							String ci = ucpidResponse.getCi();
							String ci2 = ucpidResponse.getCi2();

						} else {
							System.out.println("your UCPIDResponse is invalid. your error code is \"" + status + "\"");
						}
					}
				}
			}
		}
	}
	public static byte[] request2UCPID(byte[] UCPIDRequest,String serverIp, int serverPort){
		
		Socket socket = null;
		DataInputStream reader = null;
		DataOutputStream writer = null;
		byte[] UCPIDResponse = null;
		
		try{
			socket = new Socket(serverIp, serverPort);
			if(socket != null){
				if(socket.isConnected()){
					
					writer = new DataOutputStream(socket.getOutputStream());
					if(writer != null){
						writer.writeInt(UCPIDRequest.length);
						writer.write(UCPIDRequest,0,UCPIDRequest.length);
						writer.flush();
					}
					reader = new DataInputStream(socket.getInputStream());
					if(reader!=null){
						int readInt = reader.readInt();
						UCPIDResponse = new byte[readInt];
						reader.readFully(UCPIDResponse);
					}
				}
			}
		}catch(IOException e){
			e.printStackTrace();
		}finally{
				try {
					if(socket!=null) socket.close();
					if(writer!=null) writer.close();
					if(reader!=null) reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
		return UCPIDResponse;
	}
}

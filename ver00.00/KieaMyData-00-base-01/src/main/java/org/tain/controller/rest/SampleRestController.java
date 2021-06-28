package org.tain.controller.rest;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.tain.tools.node.MonJsonNode;
import org.tain.utils.IpPrint;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/rest")
@Slf4j
public class SampleRestController {

	/*
	 * curl -X POST -H "Content-Type: application/json" -d @./test.json http://localhost:8080/v0.1/rest/test
	 */
	@CrossOrigin(origins="*", methods = {RequestMethod.GET, RequestMethod.POST}, maxAge = 3600)
	@RequestMapping(value = {"/test"}, method = {RequestMethod.GET, RequestMethod.POST})
	public ResponseEntity<?> selectAll(HttpEntity<String> httpEntity) throws Exception {
		MonJsonNode nodeReq = null;
		if (Boolean.TRUE) {
			HttpHeaders headers = httpEntity.getHeaders();
			String body = httpEntity.getBody();
			nodeReq = new MonJsonNode(body == null ? "{}" : body);
			log.info(">>>>> ip.info: " + IpPrint.get());
			log.info(">>>>> request.headers: " + headers.toString());
			log.info(">>>>> request.body: " + body);
			log.info(">>>>> request.body.JSON: " + nodeReq.toPrettyString());
		}
		
		MonJsonNode nodeRes = null;
		if (Boolean.TRUE) {
			nodeRes = new MonJsonNode("{}");
			nodeRes.put("name", "Hello, workd!!!");
			log.info(">>>>> mapRes: {}", nodeRes);
		}
		
		MultiValueMap<String,String> headers = null;
		if (Boolean.TRUE) {
			headers = new LinkedMultiValueMap<>();
			headers.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8");
		}
		return new ResponseEntity<>(nodeRes.getJsonNode(), headers, HttpStatus.OK);
	}
}

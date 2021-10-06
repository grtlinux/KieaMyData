package org.tain.controller.rest;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping(value = {"/store"}, method = {RequestMethod.GET, RequestMethod.POST})
public class StoreAuthController {

	final private ObjectMapper objectMapper = new ObjectMapper();
	
	@RequestMapping(value = {"/auth"}, method = {RequestMethod.GET, RequestMethod.POST})
	public ResponseEntity<?> auth(HttpEntity<String> reqEntity) throws Exception {
		if (Boolean.TRUE) {
			String reqBody = reqEntity.getBody();
			if (reqBody == null || "".equals(reqBody))
				reqBody = "{}";
			JsonNode node = this.objectMapper.readTree(reqBody);
			String json = this.objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(node);
			System.out.println(">>>>> JSON : " + json);
		}
		
		Map<String, Object> mapOut = null;
		if (Boolean.TRUE) {
			mapOut = new HashMap<>();
			mapOut.put("resStatus", "SUCCESS");
		}
		
		MultiValueMap<String, String> resHeaders = null;
		if (Boolean.TRUE) {
			resHeaders = new LinkedMultiValueMap<>();
			resHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF8");
		}
		
		return new ResponseEntity<>(mapOut, resHeaders, HttpStatus.OK);
	}
}

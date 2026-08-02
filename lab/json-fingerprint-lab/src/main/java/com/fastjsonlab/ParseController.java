package com.fastjsonlab;

import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ParseController {

    private final ObjectMapper jackson = new ObjectMapper();
    private final Gson gson = new Gson();

    static {
        // Keep default safeMode behavior of 1.2.83 so @type probe yields autoType message.
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("status", "ok");
        body.put("endpoints", new String[]{
                "/api/fastjson",
                "/api/fastjson/autotype",
                "/api/fastjson/silent",
                "/api/fastjson/silent/autotype",
                "/api/fastjson/person",
                "/api/jackson",
                "/api/jackson/person",
                "/api/gson",
                "/api/orgjson",
                "/api/hutool"
        });
        return body;
    }

    @PostMapping(value = "/fastjson", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fastjson(HttpServletRequest request) {
        try {
            Object obj = JSON.parse(readBody(request));
            return ResponseEntity.ok(JSON.toJSONString(obj));
        } catch (Exception e) {
            return error(e);
        }
    }

    /**
     * Fastjson with autoType enabled — used to verify DNSLog / gadget probes in lab.
     */
    @PostMapping(value = "/fastjson/autotype", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fastjsonAutoType(HttpServletRequest request) {
        try {
            ParserConfig cfg = new ParserConfig();
            cfg.setSafeMode(false);
            cfg.setAutoTypeSupport(true);
            Object obj = JSON.parse(readBody(request), cfg);
            return ResponseEntity.ok(JSON.toJSONString(obj));
        } catch (Exception e) {
            return error(e);
        }
    }

    /**
     * No exception echo — mimics production handlers that return opaque 500.
     */
    @PostMapping(value = "/fastjson/silent", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fastjsonSilent(HttpServletRequest request) {
        try {
            Object obj = JSON.parse(readBody(request));
            return ResponseEntity.ok(JSON.toJSONString(obj));
        } catch (Exception e) {
            return silentError();
        }
    }

    @PostMapping(value = "/fastjson/silent/autotype", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fastjsonSilentAutoType(HttpServletRequest request) {
        try {
            ParserConfig cfg = new ParserConfig();
            cfg.setSafeMode(false);
            cfg.setAutoTypeSupport(true);
            Object obj = JSON.parse(readBody(request), cfg);
            return ResponseEntity.ok(JSON.toJSONString(obj));
        } catch (Exception e) {
            return silentError();
        }
    }

    @PostMapping(value = "/fastjson/person", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fastjsonPerson(HttpServletRequest request) {
        try {
            Person person = JSON.parseObject(readBody(request), Person.class);
            return ResponseEntity.ok(JSON.toJSONString(person));
        } catch (Exception e) {
            return error(e);
        }
    }

    @PostMapping(value = "/jackson", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jackson(HttpServletRequest request) {
        try {
            Object obj = jackson.readValue(readBody(request), Object.class);
            return ResponseEntity.ok(jackson.writeValueAsString(obj));
        } catch (Exception e) {
            return error(e);
        }
    }

    @PostMapping(value = "/jackson/person", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jacksonPerson(HttpServletRequest request) {
        try {
            Person person = jackson.readValue(readBody(request), Person.class);
            return ResponseEntity.ok(jackson.writeValueAsString(person));
        } catch (Exception e) {
            return error(e);
        }
    }

    @PostMapping(value = "/gson", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> gson(HttpServletRequest request) {
        try {
            Object obj = gson.fromJson(readBody(request), Object.class);
            return ResponseEntity.ok(gson.toJson(obj));
        } catch (Exception e) {
            return error(e);
        }
    }

    @PostMapping(value = "/orgjson", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> orgJson(HttpServletRequest request) {
        try {
            JSONObject obj = new JSONObject(readBody(request));
            return ResponseEntity.ok(obj.toString());
        } catch (Exception e) {
            return error(e);
        }
    }

    @PostMapping(value = "/hutool", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> hutool(HttpServletRequest request) {
        try {
            return ResponseEntity.ok(JSONUtil.parse(readBody(request)).toString());
        } catch (Exception e) {
            return error(e);
        }
    }

    private String readBody(HttpServletRequest request) throws Exception {
        return StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
    }

    private ResponseEntity<String> error(Exception e) {
        Map<String, Object> payload = new HashMap<String, Object>();
        payload.put("error", e.getClass().getName());
        payload.put("message", e.getMessage() == null ? e.toString() : e.getMessage());
        payload.put("detail", e.toString());
        return ResponseEntity.badRequest()
                .contentType(MediaType.APPLICATION_JSON)
                .body(JSON.toJSONString(payload));
    }

    private ResponseEntity<String> silentError() {
        return ResponseEntity.status(500)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"ok\":false}");
    }
}

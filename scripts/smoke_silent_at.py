import httpx

payloads = {
    "class": '{"xxx":{"@type":"java.lang.Class","val":""}}',
    "random": '{"xxx":{"@type":"Random.String"}}',
}
for port in (18030, 18082, 18080):
    for name, body in payloads.items():
        r = httpx.post(
            f"http://127.0.0.1:{port}/api/fastjson/silent/autotype",
            content=body.encode(),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        print(port, name, r.status_code, r.text[:80])

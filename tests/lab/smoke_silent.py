import httpx

for port in (18030, 18047, 18068, 18082, 18080):
    url = f"http://127.0.0.1:{port}/api/fastjson/silent"
    r = httpx.post(
        url,
        content=b'{"@type":',
        headers={"Content-Type": "application/json"},
        timeout=5,
    )
    print(port, r.status_code, r.text)

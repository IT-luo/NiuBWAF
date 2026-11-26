const http = require('http');
http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
  res.end(`<!doctype html><meta charset="utf-8"><title>测试上游站点</title>
<body style="font-family:sans-serif;padding:40px">
<h1>上游业务站点（模拟）</h1>
<p>这是被NiuB WAF 保护的真实业务服务器。</p>
<p>请求路径: ${req.url}</p>
<p>X-NiuB-WAF-Req-ID: ${req.headers['x-niub-waf-req-id'] || '(无)'}</p>
</body>`);
}).listen(8081, '127.0.0.1', () => console.log('upstream on :8081'));
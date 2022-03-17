require('http').createServer((req, res) => {
    console.log(req.method, req.url)
    res.end('hello from behind the proxy!\n')
}).listen(8080)

Synopsis
========
```conf
worker_processes  1;        #nginx worker 数量
error_log logs/error.log info;   #指定错误日志文件路径
user root;
events {
    worker_connections 1024;
}

http {
    lua_package_cpath '/root/dyna/ffi/target/debug/?.so;;';
    lua_package_path '/root/or/lua/?.lua;/root/lua-resty-dynafilter/lib/resty/?.lua;;';
    init_worker_by_lua_block {
        --local dyna = require ("dyna")
        --dyna:new()
    }
    server {
        listen    8088;

        location / {
            access_by_lua_block {
                local dyna = require ("dyna")
                dyna:new()
                dyna:exec()
                dyna:free()
                ngx.log(ngx.ERR, "access in")
                ngx.status = ngx.HTTP_METHOD_NOT_IMPLEMENTED
                ngx.exit(501)
            }
        }
    }
}
```
```lua
local ffi = require("ffi")
local _M = {}
local dynafilter = require("dynafilter")
local cjson = require("cjson")

function _M:new()
    local df, err = dynafilter:new({
        fields = {
            ["keyword"] = dynafilter.types.BYTES,
            ["RESPONSE_STATUS"] = dynafilter.types.BYTES,
            ["RESPONSE_HEADER"] = dynafilter.types.BYTES,
            ["RESPONSE_BODY"] = dynafilter.types.BYTES,
        },
        rules = {
            {id = "080080001", rule = "prefilter(keyword, \"RESPONSE_HEADER\",\"628\",\" 5\",\"none\") && (RESPONSE_STATUS matches \"XjVcZHsyfSQ=\")"},
            {id = "080150002", rule = "prefilter(keyword, \"RESPONSE_BODY\",\"332\",\"fopen\",\"both\") && (RESPONSE_BODY matches \"XGIoZm9wZW4pXGI=\")"}
        }
    })
    if err ~= nil then
        ngx.log(ngx.ERR, "dynafilter new faild:" .. err)
    end

    self.dyna = df

end

function _M:exec()
    local match_result, err = self.dyna:exec({
        ["RESPONSE_STATUS"] = "501",
        ["RESPONSE_HEADER"] = "HTTP/1.1 501 Method Not Implemented\r\nDate: Sun, 06 Nov 2011 08:20:35 GMT\r\nServer: Apache/2.2.17 (Unix) PHP/5.3.5\r\nX-Powered- By: PHP/5.3.5\r\nContent-Length: 154\r\nContent-Type: text/html",
        ["RESPONSE_BODY"] = "<head>\r\n<title>501 Method Not Implemented</title>\r\n</head>\r\n<body>\r\n<h1>Method Not Implemented</h1>\r\n<p>GET to /e/501 not  supported.</p>\r\n</body>\r\n</html>"
    })
    if err ~= nil then
        ngx.say("exec faild:" .. err)
    else
        ngx.log(ngx.ERR, "match result: ", match_result)
        --ngx.status = ngx.HTTP_METHOD_NOT_IMPLEMENTED
        --ngx.exit(501)
    end
end

function _M:free()
    self.dyna:clear()
    self.dyna = nil
end

return _M
```

Synopsis
========
```lua
local dynafilter = require "resty.dynafilter"
local df, err = dynafilter:new({
    fields = {
        ["keyword"]: Bytes,
        ["RESPONSE_STATUS"]: Bytes,
        ["RESPONSE_HEADER"]: Bytes,
        ["RESPONSE_BODY"]: Bytes,
    },
    rules = {
        {id = "080080001", rule = "prefilter(keyword, \"RESPONSE_HEADER\",\"628\",\" 5\",\"none\") && (RESPONSE_STATUS matches \"XjVcZHsyfSQ=\")"},
        {id = "080150002", rule = "prefilter(keyword, \"RESPONSE_BODY\",\"332\",\"fopen\",\"both\") && (RESPONSE_BODY matches \"XGIoZm9wZW4pXGI=\")"}
    },
    rules = {
        ["080080001"] = {
            rule = "prefilter(keyword, \"RESPONSE_HEADER\",\"628\",\" 5\",\"none\") && (RESPONSE_STATUS matches \"XjVcZHsyfSQ=\")",
            risk_level = 1
        },
        ["080150002"] = {
            rule = "prefilter(keyword, \"RESPONSE_BODY\",\"332\",\"fopen\",\"both\") && (RESPONSE_BODY matches \"XGIoZm9wZW4pXGI=\")",
            risk_level = 1
        }
    }
    rules = "[{\"id\":\"080080001\",\"rule\":\"prefilter(keyword, \\\"RESPONSE_HEADER\\\",\\\"628\\\",\\\" 5\\\",\\\"none\\\") && (RESPONSE_STATUS matches \\\"XjVcZHsyfSQ=\\\")\"},{\"id\":\"080150002\",\"rule\":\"prefilter(keyword, \\\"RESPONSE_BODY\\\",\\\"332\\\",\\\"fopen\\\",\\\"both\\\") && (RESPONSE_BODY matches \\\"XGIoZm9wZW4pXGI=\\\")\"}]"
})
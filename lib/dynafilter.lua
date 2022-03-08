local ffi      = require("ffi")
local ffi_cdef = ffi.cdef
local ffi_load = ffi.load
local ffi_new  = ffi.new

local dynafilter = ffi_load "dynafilter"

ffi_cdef [[
    typedef struct dynafilter_scheme dynafilter_scheme_t;
    typedef struct dynafilter_execution_context dynafilter_execution_context_t;
    typedef struct dynafilter_match_fields dynafilter_match_fields_t;
    typedef struct dynafilter_rule_filter dynafilter_rule_filter_t;
    typedef struct dynafilter_prefilter dynafilter_prefilter_t;

    typedef struct {
        const char *data;
        size_t length;
    } dynafilter_rust_allocated_str_t;

    typedef struct {
        const char *data;
        size_t length;
    } dynafilter_externally_allocated_str_t;

    typedef enum {
        DF_TYPE_IP,
        DF_TYPE_BYTES,
        DF_TYPE_INT,
        DF_TYPE_BOOL,
    }

    dynafilter_scheme_t *dynafilter_create_scheme();
    void dynafilter_free_scheme(dynafilter_scheme_t *scheme);

    void dynafilter_add_type_field_to_scheme(
        dynafilter_scheme_t *scheme,
        dynafilter_externally_allocated_str_t name,
        dynafilter_type_t type
    );

    void dynafilter_add_prefilter_function_to_scheme(
        dynafilter_scheme_t *scheme
    );

    dynafilter_match_fields_t *dynafilter_create_match_fields(void);

    void dynafilter_free_match_fields(
        dynafilter_match_fields_t *fields
    );

    void dynafilter_add_bytes_value_to_match_fields(
        dynafilter_match_fields_t *fs,
        dynafilter_externally_allocated_str_t name,
        dynafilter_externally_allocated_byte_arr_t value
    );

    dynafilter_rule_filter_t *dynafilter_compile_rule_filter(
        const dynafilter_scheme_t *scheme,
        dynafilter_externally_allocated_str_t input
    );

    void dynafilter_rule_filter_free(
        dynafilter_rule_filter_t *rf
    );

    dynafilter_prefilter_t *dynafilter_compile_prefilter(
        dynafilter_rule_filter_t *rf
    );

    void dynafilter_prefilter_free(
        dynafilter_prefilter_t *pf
    );

    dynafilter_rust_allocated_str_t *dynafilter_match(
        const dynafilter_scheme_t *scheme,
        dynafilter_rule_filter_t *rf,
        dynafilter_prefilter_t *pf,
        dynafilter_match_fields_t *fs
    );

    void dynafilter_free_string(dynafilter_rust_allocated_str_t str);


]]

local _M = {
    _VERSION = '0.0.1',
    types = {
        BYTES = ffi.C.DF_TYPE_BYTES,
        IP    = ffi.C.DF_TYPE_IP,
        BOOL  = ffi.C.DF_TYPE_BOOL,
        INT   = ffi.C.DF_INT,
    }
}

local mt = {
    __index = _M
}

function _M:new(args)
    local args   = args or {}
    local fields = args or {}
    local rules  = args.rules or ""
    local fields_map = {}

    local scheme, err = self:init_scheme(fields, fields_map)
    if (scheme == nil) then
        return nil, err
    end

    local rf, err = self:create_rule_filter(scheme, args.rules)
    if (rf == nil) then
        return nil, err
    end

    local pf, err = self:create_rule_prefilter(rf)
    if (pf == nil) then
        return nil, err
    end

    local self = {
        scheme = scheme,
        rule_filter = rf,
        pre_filter = pf,
        fields_map = fields_map
    }
    return setmetatable(self, mt)
end

function _M:create_rule_prefilter(rule_filter)
    
    local pf = ffi_new("dynafilter_prefilter_t*")
    local pf = dynafilter.dynafilter_compile_prefilter(rule_filter)

    if (pf == nil) then
        return nil, "could not compile prefilter"
    end

    return pf
end

function _M:create_rule_filter(scheme, rules_string)
    
    local rf = ffi_new("dynafilter_rule_filter_t*")
    local rf = dynafilter.dynafilter_compile_rule_filter(scheme, self:dynafilter_string(rules_string))

    if (rf == nil) then
        return nil, "could not compile rule filter"
    end

    return rf
end

function _M:init_scheme(fields, fields_map)
    local scheme, err = self:create_scheme()
    if (scheme == nil) then
        return nil, err
    end

    for name, type in pairs(fields) do
        self:add_type_field_to_scheme(scheme, fields_map, name, type)
    end

    self:dynafilter_add_prefilter_function_to_scheme(scheme)

    return scheme
end

function _M:add_filter_function(scheme)
    dynafilter.dynafilter_add_filter_function(scheme) 
end

function _M:add_type_field_to_scheme(scheme, fields_map, name, type)
    dynafilter.dynafilter_add_type_field_to_scheme(scheme, self:dynafilter_string(name), type)
    fields_map[name] = type
end

function _M:dynafilter_string(value)
    local value = tostring(value)
    local str = ffi_new("dynafilter_externally_allocated_str_t", {
        data = value,
        length = string.len(value)
    })
    return str
end

function _M:create_scheme()
    local scheme = ffi_new("dynafilter_scheme_t*")
    local scheme = dynafilter.dynafilter_create_scheme()

    if (scheme == nil) then
        return nil, "could not create scheme"
    end

    return scheme
end

function _M:exec(values)
    local fds, err = self:create_match_fields()
    if fds == nil then
        return nil, err
    end

    for name, value in pairs(values) do
        local result, err = self:add_value_to_execution_fields(fds, {name = name, value = value})
        if not result then
            return nil, err
        end
    end

    local match_result = self:match(fds)
    self:free_execution_fields(fds)

    return match_result
end

function _M:free_execution_fields(fields)
    dynafilter.dynafilter_free_match_fields(fields)
end

function _M:match(fields)
    local match_result = dynafilter.dynafilter_match(self.scheme, self.rule_filter, self.pre_filter, fields)
    return match_result
end

function _M:add_value_to_execution_fields(fs, value)
    local field, err = self:get_field(value)
    if field == nil then
        return false, err
    end

    if (field == self.types.BYTES) then
        dynafilter.dynafilter_add_bytes_value_to_match_fields(fs, self:dynafilter_string(value.name),
            self.dynafilter_string(value.value))
    end

    return true
end

function _M:get_field(value)
    local field = self.fields_map[value.name]
    if field == nil then
        return nil, "field does not exist"
    end 

    return field
end

function _M:create_match_fields()
    local fields = ffi_new("dynafilter_match_fields_t *")
    local fields = dynafilter.dynafilter_create_match_fields()
    if (fields == nil) then
        return nil, "could not create match fields"
    end

    return fields
end
local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local jwt_decoder = require "kong.plugins.jwt-header.jwt_parser"


local JwtHeaderHandler = BasePlugin:extend()

JwtHeaderHandler.PRIORITY = 1000

--- Retrieve a JWT in a request.
-- Checks for the JWT in header
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(request, conf)
  header_param = conf.header_param_name
  if not header_param then
    return nil, {status = 401, message = "Header Param Not Define"}
  end

  local token = request.get_headers()[header_param]
  if not token then
    return nil, {status = 401, message = "Token Not Found"}
  end
  return token
end


function JwtHeaderHandler:new()
  JwtHeaderHandler.super.new(self, "jwt-header")
end


local function do_authentication(conf)
  local token, err = retrieve_token(ngx.req, conf)
  if err then
    return false, err
  end

  local ttype = type(token)
  if ttype ~= "string" then
    if ttype == "nil" then
      return false, {status = 401}
    elseif ttype == "table" then
      return false, {status = 401, message = "Multiple tokens provided"}
    else
      return false, {status = 401, message = "Unrecognizable token"}
    end
  end

  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder:new(token)
  if err then
    return false, {status = 401, message = "Bad token; "..tostring(err)}
  end

  -- Retrieve the secret
  local algorithm = conf.algorithm or "HS256"

  -- Verify "alg"
  if jwt.header.alg ~= algorithm then
    return false, {status = 403, message = "Invalid algorithm"}
  end

  -- TODO in envirment
  local jwt_secret_value = algorithm == "HS256" and conf.secret or nil
  if not jwt_secret_value then
    return false, {status = 403, message = "Invalid key/secret"}
  end

  -- Now verify the JWT signature
  if not jwt:verify_signature(jwt_secret_value) then
    return false, {status = 403, message = "Invalid signature"}
  end

  -- Verify the JWT registered claims
  local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok_claims then
    return false, {status = 401, message = errors}
  end

  return true
end


function JwtHeaderHandler:access(conf)
  JwtHeaderHandler.super.access(self)

  local ok, err = do_authentication(conf)
  if not ok then
    return responses.send(err.status, err.message)
  end
end


return JwtHeaderHandler

local utils = require "kong.tools.utils"


return {
  no_consumer = true,
  fields = {
    secret = {type = "string", default = "secret", required = true},
    algorithm = {type = "string", default = "HS256", required = true},
    header_param_name = {type = "string", default = "token", required = true},
    claims_to_verify = {type = "array", enum = {"exp", "nbf"}},
  }
}

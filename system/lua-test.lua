#!/usr/bin/lua5.3

local system = require "system"

local hostip = arg[1]
local portno = arg[2]
if type(hostip) ~= "string" then
	io.stderr:write("Error, invalid type of hostip\n")
	io.stderr:flush()
	os.exit(1)
end
if portno then portno = tonumber(portno) end
if not portno then
	io.stderr:write("Error, invalid type of port-number\n")
	io.stderr:flush()
	os.exit(2)
end
print(system.tcpcheck(hostip, portno))
os.exit(0)

#!/usr/bin/env lua

local sysutil = require "sysutil"

io.stdout:write("Input your password:\n")
io.stdout:flush()
local passwd = sysutil.readpass(true)
if passwd then
	io.stdout:write(string.format("Your password: %s\n", passwd))
	io.stdout:flush()
else
	io.stderr:write("Error, failed to read password\n");
	io.stderr:flush()
end
os.exit(0)

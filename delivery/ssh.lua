#!/usr/bin/lua

-- Copyright 2023 Ye Holmes <yeholmes@outlook.com>
-- Licensed under the Apache License, Version 2.0
-- SSH command-line module for Lua

local sysutil = require "sysutil"

local ssht = {}
local sshmt = {}
local sfmt = string.format

-- use legacy SCP protocol for `scp:
ssht["opt_scp"] = false
ssht["set_scp"] = function (okay)
	ssht["opt_scp"] = okay
end
ssht["opt_rsa"] = false
ssht["set_rsa"] = function (okay)
	ssht["opt_rsa"] = okay
end
ssht["opt_ident"] = false
ssht["set_ident"] = function (ident)
	if type(ident) ~= "string" then
		ssht["opt_ident"] = false
		return true
	end
	local idst = sysutil.stat(ident)
	if type(idst) ~= "table" or not idst["isreg"] then
		io.stderr:write(sfmt("Error, invalid identity file: '%s'\n", ident))
		io.stderr:flush()
		return false
	end
	ssht["opt_ident"] = "-oIdentityFile=" .. ident
	return true
end

ssht["cpath"] = function (uhost, port)
	if type(uhost) ~= "string" or #uhost == 0 then
		io.stderr:write("Error, invalid user@host specified.\n")
		io.stderr:flush()
		return nil
	end

	if port == nil then port = 22 end
	if type(port) == "string" then port = tonumber(port) end
	if type(port) ~= "number" or port <= 0 or port >= 65536 then
		io.stderr:write(sfmt("Error, invalid port number for '%s'\n", uhost))
		io.stderr:flush()
		return nil
	end

	local chksum = sysutil.sha256(sfmt("%s:%d", uhost, port), false)
	if type(chksum) ~= "string" or #chksum < 12 then
		io.stderr:write(sfmt("Error, compute sha256 for '%s:%d'\n", uhost, port))
		io.stderr:flush()
		return nil
	end

	local fixstr = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	local fixlen = string.len(fixstr)
	local cpath = {}
	for idx = 1, 12 do
		local rem = string.byte(chksum, idx) % fixlen
		cpath[idx] = fixstr:sub(rem, rem)
	end
	cpath = table.concat(cpath)
	return ".ctrl-" .. cpath
end

local function ssh_close(self)
	if type(self) ~= "table" or not self.cpath then
		return false -- already closed
	end
	local port, uhost, cpath = self.port, self.uhost, self.cpath
	self.port, self.uhost, self.cpath = nil, nil, nil

	local sshcmd, an = { [1] = "ssh" }, 1
	an = an + 1; sshcmd[an] = "-oStrictHostKeyChecking=no"
	an = an + 1; sshcmd[an] = "-oUserKnownHostsFile=/dev/null"
	an = an + 1; sshcmd[an] = sfmt("-oPort=%d", port)
	an = an + 1; sshcmd[an] = "-O"
	an = an + 1; sshcmd[an] = "exit"
	an = an + 1; sshcmd[an] = "-oControlPath=" .. cpath
	an = an + 1; sshcmd[an] = uhost
	local okay, output = sysutil.call(sysutil.OPT_OUTALL, sshcmd)
	if okay == 0 and type(output) == "string" then
		-- io.stdout:write(output)
		-- io.stdout:flush()
		return true
	end
	io.stderr:write(sfmt("Error, ssh.close('%s', %s)\n", uhost, port))
	io.stderr:flush()
	return false
end

local function validate_uhost(upval)
	if type(upval) ~= "string" or #upval == 0 then
		return false
	end
	local forbit = { "\"", "'", "$", "\\", "`", }
	for _, cha in ipairs(forbit) do
		if string.find(upval, cha, 1, true) then
			return false
		end
	end
	return true
end

ssht["open"] = function (uhost, cpath, pno)
	local port = pno
	if pno == nil then port = 22 end
	if type(pno) == "string" then port = tonumber(pno) end
	if type(port) ~= "number" or port <= 0 or port >= 65536 then
		io.stderr:write("Error, invalid port for ssh-open\n")
		io.stderr:flush()
		return false
	end

	if not validate_uhost(uhost) then
		io.stderr:write("Error, invalid user-host for ssh-open\n")
		io.stderr:flush()
		return false
	end

	if not validate_uhost(cpath) then
		io.stderr:write("Error, invalid control-path for ssh-open\n")
		io.stderr:flush()
		return false
	end

	local sshcmd, an = { [1] = "ssh" }, 1
	if ssht.opt_rsa then
		an = an + 1; sshcmd[an] = "-oHostKeyAlgorithms=+ssh-rsa"
		an = an + 1; sshcmd[an] = "-oPubkeyAcceptedAlgorithms=+ssh-rsa"
	end
	if ssht["opt_ident"] then an = an + 1; sshcmd[an] = ssht["opt_ident"] end
	an = an + 1; sshcmd[an] = "-oStrictHostKeyChecking=no"
	an = an + 1; sshcmd[an] = "-oUserKnownHostsFile=/dev/null"
	an = an + 1; sshcmd[an] = "-oTCPKeepAlive=yes"
	an = an + 1; sshcmd[an] = "-oConnectionAttempts=3"
	an = an + 1; sshcmd[an] = "-oConnectTimeout=6"
	an = an + 1; sshcmd[an] = "-oServerAliveCountMax=4"
	an = an + 1; sshcmd[an] = "-oServerAliveInterval=20"
	an = an + 1; sshcmd[an] = sfmt("-oPort=%d", port)
	an = an + 1; sshcmd[an] = "-oControlMaster=yes"
	an = an + 1; sshcmd[an] = "-oControlPath=" .. cpath
	an = an + 1; sshcmd[an] = "-oControlPersist=30"
	an = an + 1; sshcmd[an] = uhost
	an = an + 1; sshcmd[an] = sfmt('echo "== CONNECTED: %s:%d" ; exit 123', uhost, port)
	local okay = sysutil.call(0, sshcmd)
	if type(okay) == "number" and okay == 0x7b00 then
		local ssho = { ["uhost"] = uhost, ["port"] = port, ["cpath"] = cpath, ["okay"] = true }
		setmetatable(ssho, { __index = sshmt, __gc = ssh_close })
		return ssho
	end
	io.stderr:write(sfmt("Error, failed to connect to '%s' at port %d\n", uhost, port))
	io.stderr:flush()
	return false
end

sshmt["close"] = ssh_close
sshmt["call"] = function (self, shcmd, capt)
	if type(self) ~= "table" or not self.cpath then
		io.stderr:write("Error, SSH object already destroyed.\n")
		io.stderr:flush()
		return false
	end
	if type(shcmd) ~= "string" or #shcmd == 0 then
		io.stderr:write("Error, invalid shell command specified\n")
		io.stderr:flush()
		return false
	end
	if capt then capt = sysutil.OPT_OUTALL else capt = 0 end
	local sshcmd, an = { [1] = "ssh" }, 1
	an = an + 1; sshcmd[an] = "-oStrictHostKeyChecking=no"
	an = an + 1; sshcmd[an] = "-oUserKnownHostsFile=/dev/null"
	an = an + 1; sshcmd[an] = sfmt("-oPort=%d", self["port"])
	an = an + 1; sshcmd[an] = "-oControlMaster=no"
	an = an + 1; sshcmd[an] = "-oControlPath=" .. self["cpath"]
	an = an + 1; sshcmd[an] = self["uhost"]
	an = an + 1; sshcmd[an] = shcmd
	local okay, output = sysutil.call(capt, sshcmd)
	return okay, output
end

sshmt["push"] = function (self, src, dest)
	if type(self) ~= "table" or not self.cpath then
		io.stderr:write("Error, cannot copy for an invalid SSH object.\n")
		io.stderr:flush()
		return false
	end

	if type(dest) ~= "string" or #dest == 0 then
		io.stderr:write("Error, invalid destination for ssh-pull\n")
		io.stderr:flush()
		return false
	end

	local fst = sysutil.stat(src)
	if type(fst) ~= "table" or not fst["isreg"] then
		if type(src) ~= "string" then src = "unknown" end
		io.stderr:write(sfmt("Error, cannot copy '%s' for '%s', port %s\n",
			src, self.uhost, self.port))
		io.stderr:flush()
		return false
	end

	local scpcmd, an = { [1] = "scp" }, 1
	if ssht.opt_scp then an = an + 1; scpcmd[an] = "-O" end
	an = an + 1; scpcmd[an] = "-oStrictHostKeyChecking=no"
	an = an + 1; scpcmd[an] = "-oUserKnownHostsFile=/dev/null"
	an = an + 1; scpcmd[an] = sfmt("-oPort=%d", self["port"])
	an = an + 1; scpcmd[an] = "-oControlMaster=no"
	an = an + 1; scpcmd[an] = "-oControlPath=" .. self["cpath"]
	an = an + 1; scpcmd[an] = src
	an = an + 1; scpcmd[an] = sfmt("%s:%s", self["uhost"], dest)
	return sysutil.call(0, scpcmd) == 0
end

sshmt["pull"] = function (self, src, dest)
	if type(self) ~= "table" or not self.cpath then
		io.stderr:write("Error, cannot copy for an invalid SSH object.\n")
		io.stderr:flush()
		return false
	end

	if type(src) ~= "string" or #src == 0 then
		io.stderr:write("Error, invalid target source for ssh-pull\n")
		io.stderr:flush()
		return false
	end

	if type(dest) ~= "string" or #dest == 0 then
		io.stderr:write("Error, invalid local destination for ssh-pull\n")
		io.stderr:flush()
		return false
	end
	sysutil.unlink(dest) -- if `dest is not a directory, remove it

	local scpcmd, an = { [1] = "scp" }, 1
	if ssht.opt_scp then an = an + 1; scpcmd[an] = "-O" end
	an = an + 1; scpcmd[an] = "-oStrictHostKeyChecking=no"
	an = an + 1; scpcmd[an] = "-oUserKnownHostsFile=/dev/null"
	an = an + 1; scpcmd[an] = sfmt("-oPort=%d", self["port"])
	an = an + 1; scpcmd[an] = "-oControlMaster=no"
	an = an + 1; scpcmd[an] = "-oControlPath=" .. self["cpath"]
	an = an + 1; scpcmd[an] = sfmt("%s:%s", self["uhost"], src)
	an = an + 1; scpcmd[an] = dest
	return sysutil.call(0, scpcmd) == 0
end

return ssht

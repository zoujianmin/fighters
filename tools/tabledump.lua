#!/usr/bin/env lua

-- Copyright 2020 Ye Holmes <yeholmes@outlook.com>
-- 
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
-- 
--     http://www.apache.org/licenses/LICENSE-2.0
-- 
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Created by yeholmes@outlook.com
-- Simple table-dump module for Lua
-- 2020/10/26

local tabledump = {}

tabledump.dump = function (tabv, tabn)
	local typn = type(tabv)
	if typn ~= "table" then
		io.stderr:write(string.format("not a table: %s\n", typn))
		return nil
	end
	typn = type(tabn)
	if typn ~= "string" or #tabn == 0 then tabn = "TABLE" end

	local num, nlen, ntab = 0, 0, {}
	for keyv, _ in pairs(tabv) do
		typn = type(keyv)
		if typn ~= "string" then
			io.stderr:write(string.format("not a key-string: %s\n", typn))
			return nil
		end
		num = num + 1
		ntab[num] = keyv
		if #keyv > nlen then nlen = #keyv end
	end

	if num == 0 then
		print(string.format("Empty table: %s", tabn))
		return 0
	end

	nlen = nlen + 12
	if num > 1 then table.sort(ntab) end
	for _, keyv in ipairs(ntab) do
		local sepStr = "-"
		local keyVal = tabv[keyv]
		typn = type(keyVal)
		sepStr = sepStr:rep(nlen - #keyv)
		if typn == "string" then
			print(string.format("%s.%s %s %s", tabn, keyv,
				sepStr, keyVal))
		elseif typn == "number" then
			if keyVal ~= math.floor(keyVal) then
				print(string.format("%s.%s %s %s", tabn, keyv,
					sepStr, typn))
			else
				if keyVal >= 0 and keyVal <= 0xFFFFFFFF then
					print(string.format("%s.%s %s %#x", tabn, keyv,
						sepStr, keyVal))
				else
					print(string.format("%s.%s %s %d", tabn, keyv,
						sepStr, keyVal))
				end
			end
		else
			print(string.format("%s.%s %s %s", tabn, keyv,
				sepStr, typn))
		end
	end
	return num
end

return tabledump

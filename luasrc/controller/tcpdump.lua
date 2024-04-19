--[[
LuCI - Lua Configuration Interface


Copyright 2013-2014 Diego Manas <diegomanas.dev@gmail.com>

Copyright (C) 2019, KFERMercer <iMercer@yeah.net>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

$Id$

2019-07-12  modified by KFERMercer <iMercer@yeah.com>:
	format code

]] --
module("luci.controller.tcpdump", package.seeall)

tcpdump_root_folder = "/tmp/tcpdump/"
tcpdump_cap_folder = tcpdump_root_folder .. "cap/"
tcpdump_filter_folder = tcpdump_root_folder .. "filter/"
pid_file = tcpdump_root_folder .. "tcpdump.pid"
log_file = tcpdump_root_folder .. "tcpdump.log"
out_file = tcpdump_root_folder .. "tcpdump.out"
sleep_file = tcpdump_root_folder .. "tcpdump.sleep"

function index()
	template("myapp-mymodule/helloworld")
	entry({"admin", "network", "tcpdump"}, template("tcpdump"), _ "Tcpdump", 70).dependent =
		false

	page = entry({"admin", "network", "tcpdump", "capture_start"},
				 call("capture_start"), nil)
	page.leaf = true

	page = entry({"admin", "network", "tcpdump", "capture_stop"},
				 call("capture_stop"), nil)
	page.leaf = true

	page = entry({"admin", "network", "tcpdump", "update"}, call("update"), nil)
	page.leaf = true

	page = entry({"admin", "network", "tcpdump", "capture_get"},
				 call("capture_get"), nil)
	page.leaf = true

	page = entry({"admin", "network", "tcpdump", "capture_remove"},
				 call("capture_remove"), nil)
	page.leaf = true

end

function param_check(ifname, stop_value, stop_unit, filter)
	local check = false
	local message = {}
	-- Check interface
	-- Check for empty interface
	if ifname == nil or ifname == '' then
		table.insert(message, "Interface name is null or blank.")
	end
	-- Check for existing interface
	local nixio = require "nixio"
	for k, v in ipairs(nixio.getifaddrs()) do
		if v.family == "packet" then
			if ifname == v.name then
				check = true
				break
			end
		end
	end
	-- Check special interface name "any"
	if iface == 'any' then check = true end
	-- ERROR interface name not found
	if not check then
		table.insert(message, "Interface does not exist or is not valid.")
	end
	-- Check stop condition value
	if tonumber(stop_value) == nil then
		check = false
		table.insert(message, "Capture length parameter must be a number.")
	end
	-- Check stop condition flag
	if stop_unit == nil then
		check = false
		table.insert(message, "Capture unit is null or blank.")
	else
		stop_unit = string.upper(stop_unit)
		if stop_unit ~= "T" and stop_unit ~= "P" then
			check = false
			table.insert(message, "Capture unit must be Time(T) or packet(P).")
		end
	end
	return check, message
end

function capture_start(ifname, stop_value, stop_unit, filter)
	local active, pid = capture_active()
	local res = {}
	local cmd = {}
	if active then
		cmd["ok"] = false
		cmd["msg"] = {"Previous capture is still ongoing!"}
	else
		local check, msg = param_check(ifname, stop_value, stop_unit, filter)
		if not check then
			cmd["ok"] = false
			cmd["msg"] = msg
		else
			-- Create temporal folders
			os.execute("mkdir -p " .. tcpdump_cap_folder)
			os.execute("mkdir -p " .. tcpdump_filter_folder)
			os.execute("rm " .. tcpdump_cap_folder .. "*")
			os.execute("rm " .. tcpdump_filter_folder .. "*")
			local prefix = "capture_" .. os.date("%Y-%m-%d_%H.%M.%S")
			local pcap_file = tcpdump_cap_folder .. prefix .. ".pcap"
			local filter_file = tcpdump_filter_folder .. prefix .. ".filter"
			string_to_file(filter_file, filter)
			string_to_file(out_file, prefix)
			tcpdump_start(ifname, stop_value, stop_unit, filter_file, pcap_file)
			res["filter"] = filter
			cmd["ok"] = true
			cmd["msg"] = {"Capture in progress.."}
		end
	end
	res["cmd"] = cmd
	res["capture"] = capture()
	res["list"] = list()
	luci.http.prepare_content("application/json")
	luci.http.write_json(res)
end

function string_to_file(file, data)
	if data == nil then data = "" end
	local f = io.open(file, "w")
	f:write(data)
	f:close()
end

function tcpdump_start(ifname, stop_value, stop_unit, filter_file, pcap_file)
	local cmd = "tcpdump -i %s -F %s -w %s --print -v -C 10 -W 10"
	cmd = string.format(cmd, ifname, filter_file, pcap_file)
	-- Packet limit if required
	if tonumber(stop_value) ~= 0 and stop_unit == "P" then
		cmd = cmd .. " -c " .. stop_value
	end
	-- Mute output and record PID on pid_file
	cmd = string.format("%s &> %s & echo $! > %s", cmd, log_file, pid_file)
	os.execute(cmd)
	-- Time limit if required
	if tonumber(stop_value) ~= 0 and stop_unit == "T" then
		local f = io.open(pid_file, "r")
		if f ~= nil then
			local pid = f:read()
			f:close()
			local t_out =
				string.format("sleep %s && kill %s &", stop_value, pid)
			os.execute(t_out)
		end
	end
end

function capture_stop()
	local res = {}
	local cmd = {}
	local _, active, pid = capture()
	if active then
		luci.sys.process.signal(pid, 9)
		cmd["ok"] = true
		cmd["msg"] = {"Capture has been terminated"}
	else
		cmd["ok"] = false
		cmd["msg"] = {"There was not active capture!"}
	end
	capture_cleanup()
	res["cmd"] = cmd
	res["capture"] = capture()
	res["list"] = list()
	luci.http.prepare_content("application/json")
	luci.http.write_json(res)
end

function capture_active()
	local f = io.open(pid_file, "r")
	if f ~= nil then
		pid = f:read()
		f:close()
		-- Check it is a legal PID and still alive
		if tonumber(pid) ~= nil and luci.sys.process.signal(pid, 0) then
			return true, pid
		end
	end
	return false, nil
end

function capture_log()
	local log
	local f = io.open(log_file, "r")
	if f ~= nil then
		log = f:read("*all")
		f:close()
	else
		log = ""
	end
	return log
end

function capture_name()
	local cap_name = nil
	local f = io.open(out_file, "r")
	if f ~= nil then
		cap_name = f:read()
		f:close()
	end
	return cap_name
end

function capture()
	local fs = require "nixio.fs"
	local res = {}
	local active, pid = capture_active()
	local msg
	res["active"] = active
	res["log"] = capture_log()
	if active then
		res["msg"] = "Capture in progress.."
		res["cap_name"] = capture_name()
	elseif fs.access(pid_file) then
		capture_cleanup()
		res["msg"] = "Process seems to be dead, removing pid file!"
	else
		res["msg"] = "No capture in progress"
	end
	return res, active, pid
end

function capture_cleanup()
	-- Careless file removal
	os.remove(pid_file)
	os.remove(log_file)
	os.remove(out_file)
	local f = io.open(sleep_file, "r")
	if f ~= nil then
		pid = f:read()
		f:close()
		-- Kill sleep process if still alive
		if tonumber(pid) ~= nil or not luci.sys.process.signal(pid, 0) then
			luci.sys.process.signal(pid, 9)
		end
	end
	-- Careless file removal
	os.remove(sleep_file)
end

function list_entries(cap_name)
	local fs = require "nixio.fs"
	local entries = {}
	local name
	local size
	local mtime
	local filter
	local glob_str
	if cap_name == nil then
		glob_str = tcpdump_cap_folder .. "*"
	else
		glob_str = tcpdump_cap_folder .. cap_name .. ".pcap"
	end
	for file in fs.glob(glob_str) do
		name = fs.basename(file)
		size = fs.stat(file, "size")
		mtime = fs.stat(file, "ctime")
		-- Figure out if there's an associated filter
		if fs.access(tcpdump_filter_folder .. string.sub(fs.basename(file), 1, -7) .. ".filter") then
			filter = true
		else
			filter = false
		end
		table.insert(entries,
					 {name = name, size = size, mtime = mtime, filter = filter})
	end
	return entries
end

function list(cap_name)
	res = {}
	res["entries"] = list_entries(cap_name)
	res["update"] = (cap_name ~= nil)
	return res
end

function update(cap_name)
	local res = {}
	local cmd = {}
	cmd["ok"] = true
	res["cmd"] = cmd
	res["capture"] = capture()
	res["list"] = list(cap_name)
	-- Build response
	luci.http.prepare_content("application/json")
	luci.http.write_json(res)
end

function capture_get(file_type, cap_name)
	local fs = require "nixio.fs"
	if file_type == "all" then
		local cmd = "tar -cvf - --transform 's|.*/||' " .. tcpdump_cap_folder .. "* " .. tcpdump_filter_folder .. "*|gzip" 
		local download_name = 'capture-' .. os.date("%Y-%m-%d_%H.%M.%S") .. '.tar.gz'
		local handle = io.popen(cmd)
		local output = handle:read("*a")
		handle:close()

		if output ~= nil and output ~= "" then
			luci.http.prepare_content("application/x-gzip")
			luci.http.header("Content-Disposition", "attachment; filename=" .. download_name)
			luci.http.write(output)
		else
			luci.http.status(500, "Error generating output")
		end
	elseif file_type == "pcap" then
		local file = tcpdump_cap_folder .. cap_name
		local download_name = cap_name
		if fs.access(file) then
			luci.http.prepare_content("application/octet-stream")
			luci.http.header("Content-Disposition", "attachment; filename=" .. download_name)
			luci.http.write(fs.readfile(file))
		else
			luci.http.status(404, "File not found")
		end
	elseif file_type == "filter" then
		local file = tcpdump_filter_folder .. string.sub(cap_name,1,-7) .. '.filter'
		local download_name = string.sub(cap_name,1,-7) .. '.filter'
		if fs.access(file) then
			luci.http.prepare_content("application/octet-stream")
			luci.http.header("Content-Disposition", "attachment; filename=" .. download_name)
			luci.http.write(fs.readfile(file))
		else
			luci.http.status(404, "File not found")
		end
	else
		-- TODO
	end
end

function capture_remove(cap_name)
	if cap_name == 'all' then
		local fs = require "nixio.fs"
		for file in fs.glob(tcpdump_cap_folder .. "*.pcap") do
			os.remove(file)
		end
		for file in fs.glob(tcpdump_filter_folder .. "*.filter") do
			os.remove(file)
		end
	else
		-- Remove both, capture and filter file
		os.remove(tcpdump_cap_folder .. cap_name .. ".pcap")
		os.remove(tcpdump_filter_folder .. cap_name .. ".filter")
	end
	-- Return current status and list
	update()
end

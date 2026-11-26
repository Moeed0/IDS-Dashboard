-- Rule 1000104 (tls-fingerprints.rules): true the first time a device sends
-- a TLS client fingerprint, once per device and fingerprint.
--
-- The fingerprint is the JA3 text (version, ciphers, extensions, curves,
-- point formats) with the extensions sorted: Chrome and Firefox send their
-- extensions in a new order on every connection, which would make each of
-- their connections look new. GREASE values are already left out of
-- Suricata's JA3. The device is the address that opened the connection.
-- Each pair is added to the dataset tls-device-clients, which rule 1000103
-- declares and Suricata keeps in /var/lib/suricata/data.
local flow = require("suricata.flow")
local ja3 = require("suricata.ja3")
local dataset = require("suricata.dataset")

function init(args)
    return {}
end

local function sorted_extensions(text)
    local parts = {}
    for part in string.gmatch(text .. ",", "([^,]*),") do
        table.insert(parts, part)
    end
    if #parts ~= 5 then
        return text
    end
    local extensions = {}
    for number in string.gmatch(parts[3], "[^-]+") do
        table.insert(extensions, tonumber(number) or 0)
    end
    table.sort(extensions)
    parts[3] = table.concat(extensions, "-")
    return table.concat(parts, ",")
end

local devices = nil

function match(args)
    local tx = ja3.get_tx()
    if tx == nil then
        return 0
    end
    local text = tx:ja3_get_string()
    if text == nil or text == "" then
        return 0
    end
    local _, client = flow.get():tuple()
    if client == nil then
        return 0
    end
    if devices == nil then
        devices = dataset.new()
        devices:get("tls-device-clients")
    end
    local key = client .. " " .. sorted_extensions(text)
    if devices:add(key, #key) == 1 then
        return 1
    end
    return 0
end

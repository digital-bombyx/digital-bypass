local log = DLOG or print

-- шаблон
local blobs = {
	tls_firpo = "tls_clienthello_firpo_ru.bin",
	tls_retext = "tls_clienthello_retext_ai.bin",
}

local folders = { "", "bin/" }
local exedir = os.getenv("EXEDIR") 
if exedir and exedir ~= "" then
    table.insert(folders, exedir .. "/")
    table.insert(folders, exedir .. "/bin/")
end

local function load(file)
    local errors = {}

    for _, folder in ipairs(folders) do
        local path = folder .. file
        local f, err = io.open(path, "rb")

        if f then
            local data, read_error = f:read("*a")
            f:close()

            if not data then
                return nil, path .. ": " .. tostring(read_error)
            end
            return data, path
        end

        table.insert(errors, tostring(err))
    end

    return nil, table.concat(errors, "; ")
end

local names = {}
for name in pairs(blobs) do
    table.insert(names, name)
end
table.sort(names)

local count = 0
local problems = {}

for _, name in ipairs(names) do
    local data, path = load(blobs[name])

    if not data then
        table.insert(problems, name .. " : " .. path)
    elseif data == "" then
        table.insert(problems, name .. " : " .. path .. " is empty")
    else
        if _G[name] ~= nil then
            log("blobs.lua: WARNING: '" .. name .. "' already exists and will be overwritten") -- если переменная (например tls_google) уже была задана 2 раза,
        end                                                                                    -- то скрипт заменит последнее ее содержимое фейком из указанного файла

        _G[name] = data
        count = count + 1
        log("blobs.lua: " .. name .. " = " .. path .. " (" .. #data .. " bytes)")
    end
end

if #problems > 0 then
    error("blobs.lua: " .. #problems .. " of " .. #names .. " blobs failed:\n  " ..
        table.concat(problems, "\n  "), 0)
end

log("blobs.lua: " .. count .. " blobs loaded")

-- SkyluneHub Loader / STEP 3 / v0.1.0
-- Public bootstrap only. The actual SkyluneHub is not bundled in this file.
-- Channel metadata MUST be enabled and body bytes/SHA-256 MUST match before execution.
-- Default channel: stable. To opt in to beta, set getgenv().SkyluneHubLoaderChannel="beta" beforehand.
-- Diagnostics: getgenv().SkyluneHubLoaderStatus
-- IMPORTANT: Hashes inside the same GitHub repository detect mismatched data;
-- they DO NOT authenticate a compromised repository or owner account.

local PREFIX = "[SH-LOADER] "
local REPO = "YuukiKun0614/SkyluneHub-Distribution"
local RAW = "https://raw.githubusercontent.com/" .. REPO .. "/main/"
local CDN = "https://cdn.jsdelivr.net/gh/" .. REPO .. "@main/"
local MAX_SCRIPT_BYTES = 12000000
local MAX_MANIFEST_BYTES = 32768

local function printInfo(message) print(PREFIX .. tostring(message)) end
local function printError(message) warn(PREFIX .. tostring(message)) end
local function clean(value)
    local s = tostring(value or ""):gsub("[\r\n\t]", " ")
    return (#s > 160) and (s:sub(1, 160) .. "...") or s
end

local env = _G
if type(getgenv) == "function" then
    local ok, e = pcall(getgenv)
    if ok and type(e) == "table" then env = e end
end

local channel = env.SkyluneHubLoaderChannel
if channel == nil then channel = "stable" end
local forceReload = env.SkyluneHubLoaderForceReload == true
local dryRun = env.SkyluneHubLoaderDryRun == true
local previous = env.SkyluneHubLoaderStatus
local timeNow = os.clock()

if type(previous) == "table" then
    local previousAge = timeNow - (tonumber(previous.startedClock) or 0)
    if previous.active == true and previousAge >= 0 and previousAge < 180 then
        printInfo("Already fetching/starting. Duplicate Loader invocation skipped.")
        return
    end
    if previous.status == "launched" and forceReload ~= true then
        printInfo("Already launched (version " .. clean(previous.version) .. "). Set SkyluneHubLoaderForceReload=true to retry intentionally.")
        return
    end
end

local status = {
    loaderVersion="0.1.0", channel=channel, status="starting", stage="init",
    version=nil, path=nil, manifestTransport=nil, scriptTransport=nil,
    bytes=nil, hashMode=nil, verified=false, active=true,
    startedClock=timeNow, message="", error=nil,
}
env.SkyluneHubLoaderStatus = status
local function setStage(stage, message)
    status.stage=stage
    status.message=clean(message)
    printInfo(stage .. ": " .. status.message)
end
local function finish(kind, message)
    status.active=false
    status.status=kind
    status.stage=kind
    status.message=clean(message)
    if kind=="error" then
        status.error=status.message
        printError(kind .. ": " .. status.message)
    else
        printInfo(kind .. ": " .. status.message)
    end
end

local function performHttp(url)
    local attempts={}
    local function push(name, fn)
        if type(fn)=="function" then attempts[#attempts+1]={name=name,fn=fn} end
    end
    push("request", request)
    if http_request ~= request then push("http_request", http_request) end
    if type(syn)=="table" then push("syn.request", syn.request) end

    for _,api in ipairs(attempts) do
        local ok,response=pcall(api.fn,{Url=url,Method="GET"})
        if ok and type(response)=="table" then
            local code=tonumber(response.StatusCode or response.Status or response.status)
            local body=response.Body or response.body
            local good=(code==nil or (code>=200 and code<300)) and response.Success~=false
            if good and type(body)=="string" and #body>0 then
                return body,api.name .. " HTTP " .. tostring(code or "n/a")
            end
        end
    end
    local ok,body=pcall(function() return game:HttpGet(url,true) end)
    if ok and type(body)=="string" and #body>0 then
        return body,"game:HttpGet"
    end
    return nil,"all supported HTTP transports failed"
end

local function fetchFile(path,maxBytes,validate)
    local lastError="none"
    for _,origin in ipairs({{name="RAW",base=RAW},{name="CDN",base=CDN}}) do
        local body,transport=performHttp(origin.base..path)
        if body then
            if #body > maxBytes then
                lastError=origin.name .. " body too large: " .. #body
            elseif type(validate)=="function" then
                local ok,result,reason=pcall(validate,body)
                if ok and result==true then
                    return body, origin.name.."/"..transport
                end
                lastError=origin.name .. " verification: " .. clean(ok and reason or result)
            else
                return body, origin.name.."/"..transport
            end
        else
            lastError=origin.name .. ": " .. transport
        end
        printInfo("Trying next source after " .. clean(lastError))
    end
    return nil,lastError
end

local function nativeSHA256(data)
    local candidates={}
    if type(crypt)=="table" and type(crypt.hash)=="function" then
        candidates[#candidates+1]={name="crypt.hash", fn=crypt.hash}
    end
    if type(syn)=="table" and type(syn.crypt)=="table" and type(syn.crypt.hash)=="function" then
        candidates[#candidates+1]={name="syn.crypt.hash",fn=syn.crypt.hash}
    end
    for _,api in ipairs(candidates) do
        local ok,value=pcall(api.fn,data,"sha256")
        if ok and type(value)=="string" and #value==64 and value:match("^[0-9a-fA-F]+$") then
            return value:lower(),api.name
        end
    end
    return nil,nil
end

local function portableSHA256(data)
    -- Pure Luau bit32 SHA256 fallback, only used when crypt.hash is missing.
    local bit=bit32
    if not bit or type(bit.rrotate)~="function" then return nil end
    local band,bxor,bnot,rshift,rrotate=bit.band,bit.bxor,bit.bnot,bit.rshift,bit.rrotate
    local K={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    }
    local h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
    local length=#data
    local bitLength=length*8
    local lo=bitLength%4294967296
    local hi=math.floor(bitLength/4294967296)
    local function wordBytes(n)
        return string.char(band(rshift(n,24),255),band(rshift(n,16),255),band(rshift(n,8),255),band(n,255))
    end
    local missing=(56-((length+1)%64))%64
    data=data.."\128"..string.rep("\0",missing)..wordBytes(hi)..wordBytes(lo)
    local w={}
    for pos=1,#data,64 do
        -- Yield approximately once every 64 KiB for multi-megabyte Lua files.
        if pos>1 and pos%65536==1 and task and type(task.wait)=="function" then task.wait() end
        for j=0,15 do
            local p=pos+j*4
            w[j+1]=string.byte(data,p)*16777216+string.byte(data,p+1)*65536+
                string.byte(data,p+2)*256+string.byte(data,p+3)
        end
        for j=17,64 do
            local u=w[j-15]
            local v=w[j-2]
            local a=bxor(rrotate(u,7),rrotate(u,18),rshift(u,3))
            local b=bxor(rrotate(v,17),rrotate(v,19),rshift(v,10))
            w[j]=(w[j-16]+a+w[j-7]+b)%4294967296
        end
        local a,b,c,d,e,f,g,z=table.unpack(h)
        for j=1,64 do
            local big1=bxor(rrotate(e,6),rrotate(e,11),rrotate(e,25))
            local choose=bxor(band(e,f),band(bnot(e),g))
            local t1=(z+big1+choose+K[j]+w[j])%4294967296
            local big0=bxor(rrotate(a,2),rrotate(a,13),rrotate(a,22))
            local majority=bxor(band(a,b),band(a,c),band(b,c))
            local t2=(big0+majority)%4294967296
            z,g,f,e,d,c,b,a=g,f,e,(d+t1)%4294967296,c,b,a,(t1+t2)%4294967296
        end
        for j,x in ipairs({a,b,c,d,e,f,g,z}) do h[j]=(h[j]+x)%4294967296 end
    end
    return ("%08x%08x%08x%08x%08x%08x%08x%08x"):format(table.unpack(h))
end

local function verifySHA256(data,expected)
    local hash,algorithm=nativeSHA256(data)
    if hash==expected then
        status.hashMode=algorithm
        return true
    end
    -- Some executors expose nonstandard hash APIs; verify with portable SHA-256 as needed.
    local fallback=portableSHA256(data)
    if fallback==expected then
        status.hashMode="portable SHA-256"
        return true
    end
    status.hashMode=(algorithm or "none") .. " + portable"
    return false,"SHA256 mismatch (got "..clean(fallback and fallback:sub(1,16) or hash and hash:sub(1,16) or "unavailable").."...)"
end

local function main()
    if channel ~= "stable" and channel ~= "beta" then
        finish("error","Invalid channel. Use stable or beta only.")
        return
    end
    local okService,httpService=pcall(function() return game:GetService("HttpService") end)
    if not okService or not httpService then
        finish("error","HttpService unavailable")
        return
    end

    status.status="checking"
    local manifestPath="channels/"..channel..".json"
    setStage("manifest", "Fetching "..manifestPath)
    local manifestBody,manifestFrom=fetchFile(manifestPath,MAX_MANIFEST_BYTES)
    if not manifestBody then
        finish("error","Could not fetch channel manifest: "..clean(manifestFrom))
        return
    end
    status.manifestTransport=manifestFrom
    local okDecode,manifest=pcall(function() return httpService:JSONDecode(manifestBody) end)
    if not okDecode or type(manifest)~="table" then
        finish("error","Channel manifest JSON invalid")
        return
    end
    if manifest.schema~=1 or manifest.channel~=channel or type(manifest.enabled)~="boolean" then
        finish("error","Manifest schema/channel/enabled is invalid")
        return
    end
    if manifest.enabled == false then
        finish("disabled",channel .. " release is not published yet. No Lua downloaded or executed.")
        return
    end
    local version=tostring(manifest.version or "")
    if not version:match("^%d+%.%d+%.%d+$") then
        finish("error","Invalid version (expected e.g. 1.0.0)")
        return
    end
    local expectedPath="releases/v"..version.."/SkyluneHub.lua"
    if type(manifest.path)~="string" or manifest.path~=expectedPath then
        finish("error","Unapproved Lua path. Expected "..expectedPath)
        return
    end
    local bytes=tonumber(manifest.bytes)
    if bytes==nil or bytes%1~=0 or bytes<256 or bytes>MAX_SCRIPT_BYTES then
        finish("error","Manifest bytes is invalid or exceeds limit")
        return
    end
    local sha=tostring(manifest.sha256 or ""):lower()
    if #sha~=64 or not sha:match("^[0-9a-f]+$") then
        finish("error","Manifest SHA-256 invalid")
        return
    end

    status.version=version
    status.path=expectedPath
    status.bytes=bytes
    setStage("script", "Downloading "..expectedPath.." ("..bytes.." bytes expected)")
    local luaBody,luaSource=fetchFile(expectedPath,MAX_SCRIPT_BYTES,function(body)
        if #body~=bytes then return false,"size mismatch: got "..#body..", expected "..bytes end
        return verifySHA256(body,sha)
    end)
    if not luaBody then
        finish("error","Lua download/verification failed: "..clean(luaSource))
        return
    end
    status.scriptTransport=luaSource
    status.verified=true
    printInfo("Verified "..version.." | "..tostring(#luaBody).." bytes | "..clean(status.hashMode).." | "..luaSource)

    if dryRun then
        finish("verified-only","Dry run enabled; verified script, did not execute")
        return
    end
    if type(loadstring)~="function" then
        finish("error","loadstring API unavailable; verified source not executed")
        return
    end

    setStage("compile","Compiling verified Lua")
    local okCompile,chunkOrErr=pcall(loadstring,luaBody,"@SkyluneHub/"..version)
    if not okCompile or type(chunkOrErr)~="function" then
        finish("error","Lua compilation failed: "..clean(chunkOrErr))
        return
    end

    setStage("execute","Running verified SkyluneHub "..version)
    local okRun,runError=pcall(chunkOrErr)
    if not okRun then
        finish("error","Script runtime threw an error: "..clean(runError))
        return
    end
    finish("launched","Main chunk returned. Background init / AutoLoad may still be running.")
end

local ok,err=pcall(main)
if not ok then
    finish("error","Unexpected Loader error: "..clean(err))
end

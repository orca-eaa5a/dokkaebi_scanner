rule Javascript_CreateObject{
    meta:
        description = "javascript which create suspicious object"
        author = "orca.eaa5a"
        tag = "JS.Heur.CreateObject"

    strings:
        $active_x_obj = "ActiveX" nocase
        $create_obj = "CreateObj" nocase
        $file_io_chnk1 = "FileSys" nocase
        
    condition:
        any of them
}

rule Javascript_NetworkConnection{
    meta:
        description = "javascript which create network connection"
        author = "orca.eaa5a"
        tag = "JS.Heur.InternetConn"
    strings:
        $http = "http" nocase
        $method1 = "GET"
        $method2 = "POST" nocase
        $req = "req"
        $resp = "resp"
        $ip_regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    condition:
        2 of them
}

rule Javascript_FileIO{
    meta:
        description = "javascript which use suspicious file I/O method"
        author = "orca.eaa5a"
        tag = "JS.Heur.FileIO"
    strings:
        $get_folder = "GetSpecialFolder" nocase
        $file_system_obj = "saveto" nocase
    condition:
        any of them
}

rule Javascript_Shell{
    meta:
        description = "javascript which execute command"
        author = "orca.eaa5a"
        tag = "JS.Heur.Shell"
    strings:
        $mal_str1 = "wscript" nocase
        $wscript = "shell" nocase
        $execute1 = "run(" nocase
        $execute2 = "exec(" nocase
    condition:
        any of them
}
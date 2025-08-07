param (
    [string]$TenantId = "d3db0a74-8594-4ecd-99e4-f7cfc9188187",
    [string]$ClientId = "7b1ccc2b-27a4-4ff4-b59f-01762c526f25", #bss-dev-clientapp-ejp-batch-02
    [string]$ClientSecret = "zKE3859+QW8gTRnaZsw+OylZ4KZgnwywfb/laUucBEY=",
    [string]$roleName = "psCreateRole"
)

$resource = "https://cmktest.crm7.dynamics.com"
$authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/token"

$response = Invoke-RestMethod -Method Post -Uri $authUrl -Body @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    resource      = $resource
}

$token = $response.access_token
$headers = @{
    "Authorization"     = "Bearer $token"
    "Accept"            = "application/json"
    "OData-MaxVersion"  = "4.0"
    "OData-Version"     = "4.0"
    "Content-Type"      = "application/json; charset=utf-8"
}

#$roleName = "psCreateRole"

$getDataRequestUri='roles?$select=name,roleid&$top=5000'
# 获取所有角色并判断是否存在
$allRolesUrl = "$resource/api/data/v9.1/$($getDataRequestUri)"

Write-Host "URL: $allRolesUrl"

$roles = Invoke-RestMethod -Method Get -Uri $allRolesUrl -Headers $headers

$existing = ($roles.value | Where-Object { $_.name -eq $roleName }) | Select-Object -First 1
Write-Host $existing
if ($existing) {
    $roleId = $existing.roleid
    Write-Host "ℹ️ Role already exists: $roleName (ID: $roleId)"
} else {
    # 获取默认业务单元
    $buUrl = "$resource/api/data/v9.1/$('businessunits?$select=businessunitid&$top=1')"
    $bu = Invoke-RestMethod -Method Get -Uri $buUrl -Headers $headers
    $businessUnitId = $bu.value[0].businessunitid

    $roleBody = [ordered]@{}
    $roleBody.Add("name", $roleName)
    $roleBody.Add("businessunitid@odata.bind", "/businessunits($businessUnitId)")

    $createRoleUrl = "$resource/api/data/v9.1/roles"
    $roleResponse = Invoke-RestMethod -Method Post -Uri $createRoleUrl -Headers $headers -Body ($roleBody | ConvertTo-Json -Compress)
    $roleId = $roleResponse.roleid
    Write-Host "✅ Created new role: $roleName (ID: $roleId)"
}

# 获取全部权限
$privilegeUrl = "$resource/api/data/v9.1/privileges"
$privileges = Invoke-RestMethod -Method Get -Uri $privilegeUrl -Headers $headers

Write-Host "privileges ->  $privileges"
$tables = @(
    @{ name = "crf6e_blobfile"; privileges = @("Create", "Read", "Write") },
    @{ name = "account"; privileges = @("Read", "AppendTo") },
    @{ name = "contact"; privileges = @("Read", "Append", "AppendTo") }
) | ForEach-Object {
    New-Object PSObject -Property $_
}

foreach ($table in $tables) {
    $entity = $table.name
    foreach ($action in $table.privileges) {

        $privName = "prv$action$entity"
        $priv = $privileges.value | Where-Object { $_.name -eq $privName }

        if ($null -ne $priv) {
            $body = @{
                "RoleId@odata.bind"      = "/roles($roleId)"
                "PrivilegeId@odata.bind" = "/privileges($($priv.privilegeid))"
                "AccessRight"            = $priv.access  # 通常是 1 = Read, 2 = Write, etc.
            } | ConvertTo-Json -Compress
            
            # $assignUrl = "$resource/api/data/v9.1/roles($roleId)/RolePrivileges"
            $assignUrl = "$($resource)/api/data/v9.1/roleprivileges"

            Write-Host "$assignUrl"
            Invoke-RestMethod -Method Post -Uri $assignUrl -Headers $headers -Body $body -ContentType "application/json"
            Write-Host "✅ Added $action on $entity"
        } else {
            Write-Host "⚠️ Privilege not found: $privName"
        }
    }
}
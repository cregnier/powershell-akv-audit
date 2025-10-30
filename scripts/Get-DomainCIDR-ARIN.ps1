param(
    [Parameter(Mandatory=$true)][string]$Domain
)

function Resolve-IPs {
    param([string]$d)
    try {
        [System.Net.Dns]::GetHostAddresses($d) |
            Where-Object { $_.AddressFamily -in ('InterNetwork','InterNetworkV6') } |
            ForEach-Object { $_.IPAddressToString } |
            Sort-Object -Unique
    } catch {
        Write-Error "DNS resolution failed for $d: $_"
        @()
    }
}

function Query-ARIN-RDAP {
    param([string]$ip)
    $url = "https://rdap.arin.net/registry/ip/$ip"
    try {
        Invoke-RestMethod -Uri $url -ErrorAction Stop
    } catch {
        return $null
    }
}

function Extract-ARIN-Netblocks {
    param($rdapJson)
    $blocks = @()
    if (-not $rdapJson) { return $blocks }
    # ARIN RDAP provides 'network' with 'cidr' array or 'cidr0_cidrs'
    if ($rdapJson.network) {
        $net = $rdapJson.network
        # common properties where prefixes appear
        if ($net.cidr0_cidrs) {
            foreach ($c in $net.cidr0_cidrs) {
                if ($c.v4prefix and $c.length) { $blocks += "$($c.v4prefix)/$($c.length)" }
                if ($c.v6prefix and $c.length) { $blocks += "$($c.v6prefix)/$($c.length)" }
            }
        }
        if ($net.cidr) {
            foreach ($c in $net.cidr) {
                if ($c.v4prefix and $c.length) { $blocks += "$($c.v4prefix)/$($c.length)" }
                if ($c.v6prefix and $c.length) { $blocks += "$($c.v6prefix)/$($c.length)" }
            }
        }
        # Some RDAP responses include 'remarks' or 'links' with parent/child info; include parent handle if present
        $parent = $null
        if ($net.parentHandle) { $parent = $net.parentHandle }
        $handle = $net.handle
        $name = $net.name
        $start = $net.startAddress
        $end = $net.endAddress
        foreach ($b in $blocks) {
            $blocks_result += [pscustomobject]@{
                Prefix = $b
                Handle = $handle
                Name = $name
                ParentHandle = $parent
                StartAddress = $start
                EndAddress = $end
            }
        }
    }
    return $blocks_result
}

function WhoIs-ARIN {
    param([string]$ip)
    # whois.arin.net returns textual registration info; include for additional parsing if needed
    try {
        & whois -h whois.arin.net $ip 2>$null
    } catch {
        @()
    }
}

# Main
$ips = Resolve-IPs -d $Domain
if ($ips.Count -eq 0) { Write-Error "No IPs resolved for $Domain"; exit 1 }

$results = @()

foreach ($ip in $ips) {
    Write-Output "Processing IP: $ip"
    $rdap = Query-ARIN-RDAP -ip $ip
    if ($rdap -ne $null -and $rdap.network) {
        # extract cidr blocks from RDAP network object
        $net = $rdap.network
        $handle = $net.handle
        $name = $net.name
        $parent = $net.parentHandle
        $start = $net.startAddress
        $end = $net.endAddress

        # collect CIDR entries
        $cidrs = @()
        if ($net.cidr0_cidrs) {
            foreach ($c in $net.cidr0_cidrs) {
                if ($c.v4prefix -and $c.length) { $cidrs += "$($c.v4prefix)/$($c.length)" }
                if ($c.v6prefix -and $c.length) { $cidrs += "$($c.v6prefix)/$($c.length)" }
            }
        }
        if ($net.cidr) {
            foreach ($c in $net.cidr) {
                if ($c.v4prefix -and $c.length) { $cidrs += "$($c.v4prefix)/$($c.length)" }
                if ($c.v6prefix -and $c.length) { $cidrs += "$($c.v6prefix)/$($c.length)" }
            }
        }

        if ($cidrs.Count -eq 0) {
            # fallback: try whois text parsing for route/NetRange lines
            $who = WhoIs-ARIN -ip $ip
            foreach ($line in $who) {
                if ($line -match '(?i)NetRange:\s*([0-9\.:\/\-]+)') { $cidrs += $matches[1] }
                if ($line -match '(?i)CIDR:\s*(.+)') { $cidrs += $matches[1].Split(',') | ForEach-Object { $_.Trim() } }
                if ($line -match '(?i)route:\s*([0-9./:a-fA-F]+)') { $cidrs += $matches[1] }
                if ($line -match '(?i)route6:\s*([0-9./:a-fA-F]+)') { $cidrs += $matches[1] }
            }
        }

        if ($cidrs.Count -eq 0) {
            $cidrs = @("$start-$end")
        }

        foreach ($c in ($cidrs | Sort-Object -Unique)) {
            $results += [pscustomobject]@{
                IP = $ip
                Prefix = $c
                Handle = $handle
                Name = $name
                ParentHandle = $parent
                StartAddress = $start
                EndAddress = $end
                RDAP_JSON = ($rdap | ConvertTo-Json -Depth 4)
            }
        }
    } else {
        Write-Warning "No ARIN RDAP network object found for $ip"
        $results += [pscustomobject]@{
            IP = $ip
            Prefix = ''
            Handle = ''
            Name = ''
            ParentHandle = ''
            StartAddress = ''
            EndAddress = ''
            RDAP_JSON = ''
        }
    }
}

# Output and export
if ($results.Count -gt 0) {
    $results | Select-Object IP,Prefix,Handle,Name,ParentHandle,StartAddress,EndAddress | Format-Table -AutoSize
    $csv = "$PWD\$($Domain.Replace('.','_'))_arin_prefixes.csv"
    $results | Select-Object IP,Prefix,Handle,Name,ParentHandle,StartAddress,EndAddress | Export-Csv -NoTypeInformation -Path $csv
    Write-Output "CSV exported: $csv"
} else {
    Write-Warning "No results collected."
}

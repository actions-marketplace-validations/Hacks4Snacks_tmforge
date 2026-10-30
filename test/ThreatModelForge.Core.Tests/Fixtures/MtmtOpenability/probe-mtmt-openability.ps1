#Requires -Version 5
<#
.SYNOPSIS
Reports whether the Microsoft Threat Modeling Tool can open each .tm7 in a directory.

.DESCRIPTION
Loads every model through MTMT's own ObjectModel and reads ModelLoadHasIssues / ModelLoadIssues,
which is what DashboardViewModel inspects before it raises the "coordinates are corrupted" dialog.
A model whose construction throws is a hard refusal: the tool will not open it at all.

Optionally reads one element property back through MTMT's own PropertyMap, so the answer can be
"the tool sees the value tmforge wrote" rather than only "it opened".

MTMT 7.3.51110.1 is x86 and derives its model types from WPF, so this relaunches itself under 32-bit
Windows PowerShell in STA mode.

.PARAMETER PayloadDirectory
An existing MTMT payload directory. If omitted, finds a single complete installation in the
current user's ClickOnce cache. Multiple installations require an explicit path.

.PARAMETER ModelDirectory
A directory of .tm7 files to probe.

.PARAMETER OutputPath
Where to write the JSON result. Defaults to openability.json beside the models.

.PARAMETER ElementId
Optional. The stable id of an element whose property should be read back.

.PARAMETER PropertyName
Optional. The display name of the property to read back, for example Encrypted.

.OUTPUTS
JSON on stdout and at OutputPath. Exit code 0 when every model opens, 1 when any does not, so the
script can gate a release check.
#>
[CmdletBinding()]
param(
    [string]$PayloadDirectory,
    [Parameter(Mandatory = $true)][string]$ModelDirectory,
    [string]$OutputPath,
    [string]$ElementId,
    [string]$PropertyName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This probe requires Windows, .NET Framework 4.8 and an existing MTMT installation.'
}

if ([string]::IsNullOrWhiteSpace($PayloadDirectory)) {
    $cacheDirectory = Join-Path $env:LOCALAPPDATA 'Apps\2.0'
    if (-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) {
        throw 'No ClickOnce cache was found. Specify the existing MTMT directory with -PayloadDirectory.'
    }

    $candidates = @(Get-ChildItem -LiteralPath $cacheDirectory -Filter 'ThreatModeling.Model.dll' -Recurse |
        Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.DirectoryName 'ThreatModeling.ExternalStorage.Abstracts.dll') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.DirectoryName 'ThreatModeling.ExternalStorage.Local.dll') -PathType Leaf)
        })
    if ($candidates.Count -ne 1) {
        $paths = ($candidates | ForEach-Object { $_.DirectoryName }) -join '; '
        throw "Found $($candidates.Count) complete MTMT installations. Specify -PayloadDirectory. Candidates: $paths"
    }

    $PayloadDirectory = $candidates[0].DirectoryName
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ModelDirectory 'openability.json'
}

$PayloadDirectory = [IO.Path]::GetFullPath($PayloadDirectory)
$ModelDirectory = [IO.Path]::GetFullPath($ModelDirectory)
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

$isSta = [Threading.Thread]::CurrentThread.ApartmentState -eq [Threading.ApartmentState]::STA
if ([IntPtr]::Size -ne 4 -or -not $isSta) {
    $x86PowerShell = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $x86PowerShell)) {
        throw '32-bit Windows PowerShell is required because MTMT 7.3.51110.1 is x86.'
    }

    $arguments = @(
        '-NoProfile', '-Sta', '-File', $PSCommandPath,
        '-PayloadDirectory', $PayloadDirectory, '-ModelDirectory', $ModelDirectory,
        '-OutputPath', $OutputPath)
    if (-not [string]::IsNullOrWhiteSpace($ElementId)) { $arguments += @('-ElementId', $ElementId) }
    if (-not [string]::IsNullOrWhiteSpace($PropertyName)) { $arguments += @('-PropertyName', $PropertyName) }

    & $x86PowerShell @arguments
    exit $LASTEXITCODE
}

function Format-DisplayAttribute {
    <#
    Renders one MTMT property value.

    A ListDisplayAttribute holds its options in Value as a List<string> typed as Object, so neither
    '-is [string[]]' nor GetType().IsArray identifies it; both silently fall through and print the
    whole option list instead of the selection. Materialize any non-string enumerable and index it.
    #>
    param($Attribute)

    $raw = $Attribute.Value
    if ($null -eq $raw) {
        return '<null>'
    }

    if ($raw -is [string] -or -not ($raw -is [System.Collections.IEnumerable])) {
        return [string]$raw
    }

    $options = @($raw)
    $index = -1
    try { $index = [int]$Attribute.SelectedIndex } catch { }

    if ($index -lt 0 -or $index -ge $options.Count) {
        return "<selected index $index outside $($options.Count) options>"
    }

    return [string]$options[$index]
}

function Get-EntityProperty {
    <#
    Reads one property off one element as MTMT itself resolves it.

    MTMT exposes PropertyMap (a Dictionary keyed by attribute id) rather than the raw attribute list,
    which is the interesting part: a dictionary cannot hold two entries for one key, so a file that
    carries duplicate attributes still yields a single answer here - and it need not be the answer
    tmforge's own reader produces.

    Entirely best-effort. This is supporting evidence for the load verdict, never the verdict itself,
    so every failure is reported as a string rather than thrown.
    #>
    param($Model, $ProcessingModeType, [string]$ElementId, [string]$PropertyName)

    try {
        # GetDrawingSurfaceModels() returns nothing until the model has been processed, and
        # ConfigureThreatGeneration needs a WPF dispatcher this host does not have.
        [void]$Model.ProcessModelImmediately([Enum]::Parse($ProcessingModeType, 'FullModel'))

        foreach ($surface in $Model.GetDrawingSurfaceModels()) {
            foreach ($collection in @($surface.Borders, $surface.Lines)) {
                foreach ($entity in $collection.Values) {
                    if ($null -eq $entity) { continue }

                    $guid = ''
                    try { $guid = [string]$entity.Guid } catch { continue }
                    if ($guid -ne $ElementId) { continue }

                    $map = $entity.PropertyMap
                    if ($null -eq $map) { return '<element exposes no PropertyMap>' }

                    $seen = @()
                    foreach ($key in @($map.Keys)) {
                        $attribute = $map[$key]
                        if ($null -eq $attribute) { continue }

                        $display = ''
                        try { $display = [string]$attribute.DisplayName } catch { }
                        if ($display -ne $PropertyName) { continue }

                        $seen += Format-DisplayAttribute -Attribute $attribute
                    }

                    if ($seen.Count -eq 0) { return '<property absent>' }
                    if ($seen.Count -eq 1) { return $seen[0] }
                    return ($seen -join ' | ') + " (the tool kept $($seen.Count) entries)"
                }
            }
        }

        return '<element not found>'
    }
    catch {
        return '<error: ' + $_.Exception.GetBaseException().Message + '>'
    }
}

$assemblies = @{}
foreach ($dll in Get-ChildItem -LiteralPath $PayloadDirectory -Filter '*.dll' -Recurse) {
    $assemblies[[IO.Path]::GetFileNameWithoutExtension($dll.Name)] = $dll.FullName
}

foreach ($required in @('ThreatModeling.ExternalStorage.Abstracts', 'ThreatModeling.ExternalStorage.Local', 'ThreatModeling.Model')) {
    if (-not $assemblies.ContainsKey($required)) {
        throw "The payload directory is missing '$required.dll': '$PayloadDirectory'."
    }
}

$resolver = [ResolveEventHandler] {
    param($sender, $eventArgs)

    $name = (New-Object Reflection.AssemblyName($eventArgs.Name)).Name
    if ($assemblies.ContainsKey($name)) {
        return [Reflection.Assembly]::LoadFrom($assemblies[$name])
    }

    return $null
}.GetNewClosure()

[AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
try {
    $abstracts = [Reflection.Assembly]::LoadFrom($assemblies['ThreatModeling.ExternalStorage.Abstracts'])
    $local = [Reflection.Assembly]::LoadFrom($assemblies['ThreatModeling.ExternalStorage.Local'])
    $modelAssembly = [Reflection.Assembly]::LoadFrom($assemblies['ThreatModeling.Model'])

    $storageFileType = $abstracts.GetType('ThreatModeling.ExternalStorage.Abstracts.StorageFile', $true)
    $localFileType = $local.GetType('ThreatModeling.ExternalStorage.Local.LocalFile', $true)
    $objectModelType = $modelAssembly.GetType('ThreatModeling.Model.ObjectModel', $true)
    $processingModeType = $modelAssembly.GetType('ThreatModeling.Model.ModelProcessingMode', $true)

    # Bind the constructors explicitly: PowerShell's params binding would splat a single-element
    # array. ObjectModel(String, Boolean, Boolean, Boolean) overflows the stack and kills the host
    # process, taking buffered output with it - do not use it.
    $localFileCtor = $localFileType.GetConstructor([Type[]]@([string]))
    $objectModelCtor = $objectModelType.GetConstructor([Type[]]@($storageFileType, [bool]))
    if ($null -eq $localFileCtor -or $null -eq $objectModelCtor) {
        throw 'MTMT no longer exposes LocalFile(string) or ObjectModel(StorageFile, bool).'
    }

    $models = @(Get-ChildItem -LiteralPath $ModelDirectory -Filter '*.tm7' | Sort-Object Name)
    if ($models.Count -eq 0) {
        throw "No .tm7 files were found in '$ModelDirectory'."
    }

    $results = @()
    foreach ($file in $models) {
        $record = [ordered]@{
            file = $file.Name
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = $file.Length
            opens = $false
            hasLoadIssues = $null
            loadIssues = @()
            error = $null
            errorStackTrace = $null
            observedProperty = $null
        }

        try {
            $localFile = $localFileCtor.Invoke([object[]]@([string]$file.FullName))
            $model = $objectModelCtor.Invoke([object[]]@($localFile, $false))

            $hasIssues = [bool]$model.ModelLoadHasIssues
            $record.hasLoadIssues = $hasIssues
            $record.opens = -not $hasIssues
            if ($hasIssues -and $null -ne $model.ModelLoadIssues) {
                $record.loadIssues = @($model.ModelLoadIssues | ForEach-Object { [string]$_ })
            }

            if (-not [string]::IsNullOrWhiteSpace($ElementId) -and -not [string]::IsNullOrWhiteSpace($PropertyName)) {
                $record.observedProperty = Get-EntityProperty -Model $model -ProcessingModeType $processingModeType `
                    -ElementId $ElementId -PropertyName $PropertyName
            }
        }
        catch {
            $base = $_.Exception.GetBaseException()
            $record.error = $base.GetType().FullName + ': ' + $base.Message
            $record.errorStackTrace = $base.StackTrace
        }

        $results += [pscustomobject]$record
    }

    $refused = @($results | Where-Object { -not $_.opens })
    $payload = [pscustomobject][ordered]@{
        mtmtPayloadDirectory = $PayloadDirectory
        mtmtFileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($assemblies['ThreatModeling.Model']).FileVersion
        mtmtProductVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($assemblies['ThreatModeling.Model']).ProductVersion
        modelAssembly = $modelAssembly.FullName
        modelDirectory = $ModelDirectory
        probed = $results.Count
        refused = $refused.Count
        models = $results
    }

    $json = $payload | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($OutputPath, $json)
    Write-Output $json

    if ($refused.Count -gt 0) {
        exit 1
    }
}
finally {
    [AppDomain]::CurrentDomain.remove_AssemblyResolve($resolver)
}

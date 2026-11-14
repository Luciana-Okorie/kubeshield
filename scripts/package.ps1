param(
    [string]$Output = "KubeShield-Source.zip"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outPath = Join-Path $root $Output
if (Test-Path $outPath) { Remove-Item $outPath -Force }
$items = Get-ChildItem -LiteralPath $root -Force | Where-Object {
    $_.Name -notin @(".env", ".git", "bin", "coverage.out") -and $_.FullName -ne $outPath
}
Compress-Archive -LiteralPath $items.FullName -DestinationPath $outPath -CompressionLevel Optimal
Write-Host "Created $outPath (local .env and Git history excluded)."

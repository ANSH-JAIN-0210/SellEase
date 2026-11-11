$ErrorActionPreference = 'Stop'
$projectDirectory = $PSScriptRoot
$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCommand) {
    $nodeExecutable = $nodeCommand.Source
} else {
    $workspaceDirectory = Split-Path (Split-Path $projectDirectory -Parent) -Parent
    $nodeExecutable = Join-Path $workspaceDirectory 'work\runtime\node-v24.22.2-win-x64\node.exe'
    if (-not (Test-Path -LiteralPath $nodeExecutable)) {
        throw 'Install Node.js 22.12 or newer, then run this script again.'
    }
}
$nodeDirectory = Split-Path $nodeExecutable -Parent
$npmScript = Join-Path $nodeDirectory 'node_modules\npm\bin\npm-cli.js'
if (-not (Test-Path -LiteralPath $npmScript)) {
    throw 'npm was not found beside Node.js. Install the official Node.js distribution.'
}
$env:PATH = $nodeDirectory + ';' + $env:PATH
Push-Location -LiteralPath $projectDirectory
try {
    if (-not (Test-Path -LiteralPath 'node_modules')) {
        & $nodeExecutable $npmScript ci
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    }
    & $nodeExecutable $npmScript run build
    if ($LASTEXITCODE -ne 0) { throw 'The production build failed.' }
    Write-Host 'Starting an isolated preview at http://localhost:5000. Records are discarded when stopped.'
    & $nodeExecutable $npmScript run preview -w server
} finally {
    Pop-Location
}

# PowerShell script to create a GitHub release
# Usage: This requires the GitHub CLI to be installed - run with ./create-release.ps1

# Check if gh (GitHub CLI) is installed
try {
    gh --version
}
catch {
    Write-Error "GitHub CLI (gh) is not installed. Please install it from https://cli.github.com/"
    exit 1
}

# Create the release using the payload from the file
Write-Host "Creating GitHub release for LavaBridge 1.0..."

gh release create v1.0 `
    --title "LavaBridge 1.0" `
    --notes-file release-notes.md `
    --latest `
    --repo devamop69/LavaBridge

Write-Host "Release creation completed!" 
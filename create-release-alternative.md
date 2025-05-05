# Creating the LavaBridge v1.0 Release on GitHub

Since the GitHub CLI is not installed, you can create the release manually through the GitHub web interface:

1. Go to the repository: https://github.com/devamop69/LavaBridge

2. Click on "Releases" in the right sidebar or go to https://github.com/devamop69/LavaBridge/releases

3. Click "Create a new release" or "Draft a new release"

4. Fill in the following information:
   - Tag version: `v1.0`
   - Release title: `LavaBridge 1.0`
   - Copy and paste the contents of the `release-notes.md` file into the description field

5. Make sure "Set as the latest release" is checked

6. Click "Publish release"

This will create the v1.0 release on GitHub with all the necessary information.

## Release Notes Content

For convenience, here's the content of the release notes you can copy:

```markdown
# LavaBridge 1.0 Release

The initial release of LavaBridge, a TCP tunneling proxy that routes Lavalink clients to either v3 or v4 backends based on version detection.

## Features

- Automatic routing to Lavalink v3 or v4 backends
- Low-level TCP tunneling for minimal overhead
- Modern dark-themed UI with responsive design
- Connection URL display with copy functionality
- Real-time connection monitoring
- Data usage tracking and visualization
- Security dashboard with IP blacklisting
- Health monitoring for backend servers
- Configuration via environment variables

## Configuration

See the env.sample file for all available configuration options.

## Client Connection Examples

### For v3 clients:
```
ws://your-server:6923/v3
```

### For v4 clients:
```
ws://your-server:6923/v4
```

## Project Links

- [GitHub Repository](https://github.com/devamop69/LavaBridge)
- [Documentation](https://github.com/devamop69/LavaBridge/blob/main/README.md)
``` 
# Homebrew cask for Farrier. TEMPLATE: it needs a notarized release (Developer ID) to download, which the release
# pipeline (docs/ROADMAP.md) doesn't produce yet, so this hasn't been tested. `version` and `sha256` are filled in by
# the release workflow.
cask "farrier" do
  version "0.1.0"
  sha256 :no_check

  url "https://github.com/juergen-kc/farrier/releases/download/v#{version}/Farrier-#{version}.zip"
  name "Farrier"
  desc "Keep your Mac sound from the command line and from AI agents (MCP)"
  homepage "https://github.com/juergen-kc/farrier"

  depends_on macos: ">= :sonoma"

  app "Farrier.app"

  # `farrier` must be a wrapper, not a symlink into the bundle: through a symlink the binary can't find its bundle.
  wrapper = "#{staged_path}/farrier.wrapper.sh"
  binary wrapper, target: "farrier"

  preflight do
    File.write wrapper, <<~SH
      #!/bin/sh
      exec '#{appdir}/Farrier.app/Contents/MacOS/farrier' "$@"
    SH
    FileUtils.chmod 0755, wrapper
  end

  # Root-owned, so nothing running as the user can modify the app or the helper inside it.
  postflight do
    system_command "/usr/sbin/chown", args: ["-R", "root:wheel", "#{appdir}/Farrier.app"], sudo: true
    system_command "/bin/launchctl", args: ["kickstart", "-k", "system/dev.farrier.helper"], sudo: true,
                                     must_succeed: false
  end

  uninstall script: {
    executable: "#{appdir}/Farrier.app/Contents/Resources/uninstall.sh",
    sudo:       true,
  }

  # Homebrew runs `uninstall` (which removes the app) before `zap`, so zap names the remaining data directly.
  zap trash:  [
        "~/.farrier",
        "~/Library/Application Support/Farrier",
        "~/Library/Logs/Farrier",
      ],
      delete: [
        "/Library/Application Support/Farrier",
        "/Library/Logs/farrier-helper.log",
      ]

  caveats <<~EOS
    Then, as yourself:
      farrier helper register   # allow Farrier in System Settings → General → Login Items
      farrier setup             # the approval key (an admin dialog appears)
  EOS
end

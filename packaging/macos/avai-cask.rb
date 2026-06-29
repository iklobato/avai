# Homebrew Cask template. Lives in the tap repo as Casks/avai.rb; the release
# CI fills version + sha256 and pushes it to iklobato/homebrew-avai.
#   brew install --cask iklobato/avai/avai
cask "avai" do
  version "0.0.0"
  sha256 "0" * 64

  url "https://github.com/iklobato/avai/releases/download/v#{version}/avai-#{version}.dmg"
  name "avai"
  desc "Host-security telemetry + dashboard"
  homepage "https://github.com/iklobato/avai"

  app "avai.app"

  zap trash: [
    "~/.avai",
  ]
end

class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "0.1.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "PLACEHOLDER_UPDATE_FROM_RELEASE_SHA256SUMS"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "PLACEHOLDER_UPDATE_FROM_RELEASE_SHA256SUMS"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end

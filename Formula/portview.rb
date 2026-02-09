class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "1.0.1"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "f37365c34d09be4357b7d426f19414c00312f7163bfef3b08e51e6973ea82986"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "f2f66f33fd39bc8a9e3886f793fdc77c051d82c553e897b9a8b84cf814f49e37"
    end
  end

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-x86_64.tar.gz"
      sha256 "1d64b41b45e759e8c1c86233b913e096337b4ee417a3b175eb368de339587404"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-aarch64.tar.gz"
      sha256 "b4a18ef53863c0ff2cadb60a63f0fd13a491da95a246dbc10f4a6abf5a066d49"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end

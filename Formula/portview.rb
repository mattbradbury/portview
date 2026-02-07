class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "0.3.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "5ca2aa288c34f4f8199da35acf3e91ae9904be1f64fe0c858d6ab9e745a0b60f"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "64c352286ebd61bd254b16edb13a893b79df891227a316603f570af40874635b"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end

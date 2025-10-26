# frozen_string_literal: true
source "https://rubygems.org"

ruby "~> 3.1"
gem "jekyll", "~> 4.3"

# Use the released theme gem (do NOT use `gemspec`)
gem "jekyll-theme-chirpy", "~> 7.3", group: :jekyll_plugins

# Optional: tests (avoid installing on CI via BUNDLE_WITHOUT)
group :test do
  gem "html-proofer", "~> 5.0"
end

# Windows-only helpers (safe to keep; they won’t install on Linux)
platforms :mingw, :x64_mingw, :mswin do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
  gem "wdm", "~> 0.2.0"
end

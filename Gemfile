# frozen_string_literal: true

source "https://rubygems.org"

gem "minima", "~> 2.5"

group :jekyll_plugins do
  gem "jekyll-feed"
  gem "jekyll-seo-tag"
  gem "jekyll-paginate"
  gem "jekyll-sitemap"
end

gem "html-proofer", "~> 5.0", group: :test

# Windows platform gems (tzinfo-data is still useful on Windows)
# Note: modern RubyInstaller uses :windows platform in newer Bundler
platforms :mingw, :x64_mingw, :mswin, :jruby, :windows do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# wdm removed temporarily - it requires native build tools (make).
# Use `bundle exec jekyll serve --force_polling` instead on Windows.
# gem "wdm", "~> 0.2.0", :platforms => [:mingw, :x64_mingw, :mswin]

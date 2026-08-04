$LOAD_PATH.push File.expand_path('lib', __dir__)
require_relative "lib/mta_sts/version"

Gem::Specification.new do |spec|
  spec.name = "mta_sts"
  spec.version = MtaSts::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.required_ruby_version = ">= 3.4"
  spec.authors = [ "Simon Lev" ]

  spec.summary = "SMTP MTA Strict Transport Security for Ruby."
  spec.description = "SMTP MTA Strict Transport Security for Ruby. Look up a recipient domain's MTA-STS policy before delivering a message, to know whether TLS must be enforced and which servers are legitimate."

  spec.homepage = "https://github.com/mailpiece/mta_sts"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "mta_sts.gemspec"
  ]
  spec.require_paths = [ "lib" ]

  spec.add_dependency "mailresolver"
  spec.add_dependency "simpleidn", "~> 0.2"
end

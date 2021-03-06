# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "devise/version"

Gem::Specification.new do |s|
  s.name        = "deviseOne"
  s.version     = Devise::VERSION.dup
  s.platform    = Gem::Platform::RUBY
  s.licenses    = ["MIT"]
  s.summary     = "Flexible authentication solution for Rails with Warden"
  s.email       = "rubydev@solutelabs.com"
  s.homepage    = "https://github.com/solutelabs/deviseOne"
  s.description = "Flexible Login/signup with single view"
  s.authors     = ['Solute Technolabs LLP', 'Sachin Gevariya']

  s.rubyforge_project = "deviseOne"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- test/*`.split("\n")
  s.require_paths = ["lib"]
  s.required_ruby_version = '>= 1.9.3'

  s.add_dependency("warden", "~> 1.2.3")
  s.add_dependency("orm_adapter", "~> 0.1")
  s.add_dependency("bcrypt", "~> 3.0")
  s.add_dependency("thread_safe", "~> 0.1")
  s.add_dependency("railties", ">= 3.2.6", "< 5")
  s.add_dependency("responders")

  # Add dependency for mailgun api
  s.add_dependency("multimap")
  s.add_dependency("rest-client","~> 1.7.2")
end

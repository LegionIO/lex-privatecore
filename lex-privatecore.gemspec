# frozen_string_literal: true

require_relative 'lib/legion/extensions/privatecore/version'

Gem::Specification.new do |spec|
  spec.name          = 'lex-privatecore'
  spec.version       = Legion::Extensions::Privatecore::VERSION
  spec.authors       = ['Esity']
  spec.email         = ['matthewdiverson@gmail.com']

  spec.summary       = 'LEX Private Core'
  spec.description   = 'Privacy boundary enforcement and cryptographic erasure for brain-modeled agentic AI'
  spec.homepage      = 'https://github.com/LegionIO/lex-privatecore'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.4'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/LegionIO/lex-privatecore'
  spec.metadata['documentation_uri'] = 'https://github.com/LegionIO/lex-privatecore'
  spec.metadata['changelog_uri'] = 'https://github.com/LegionIO/lex-privatecore'
  spec.metadata['bug_tracker_uri'] = 'https://github.com/LegionIO/lex-privatecore/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir.glob('{lib,spec}/**/*') + %w[lex-privatecore.gemspec Gemfile]
  end
  spec.require_paths = ['lib']
  spec.add_development_dependency 'legion-gaia'
end

#Encoding: UTF-8
=begin
This file is part of libacl-ruby. 

libacl-ruby is a Ruby binding for the C library libacl. 

Copyright © 2011 Hans Mackowiak

libacl-ruby is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

libacl-ruby is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with libacl-ruby; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
=end

require "rake"
gem "rdoc" #Ruby's internal RDoc is not really good
require "rdoc/task"
require "rake/gempackagetask"
require "rake/testtask"
require "rake/clean"

#All generated files not necessary for final use
CLEAN.include("ext/mkmf.log", "ext/Makefile", "ext/*.o")
#All generated files
CLOBBER.include("ext/*.so")

spec = Gem::Specification.new do |s|
  s.name = "libacl-ruby"
  s.summary = "Ruby bindings for libacl"
  s.description = <<DESCRIPTION
libacl-ruby provides Ruby bindings for the libacl library that 
allows you to access the Access Control Lists.
DESCRIPTION
  s.version = "0.0.1.dev"
  s.author = "Hanmac"
  s.email = "hanmac@gmx.de"
  s.platform = Gem::Platform::RUBY
  s.required_ruby_version = ">=1.9"
  #s.add_dependency("term-ansicolor", ">= 2.0.0")
  #s.add_development_dependency("rdoc", ">= 3")
  s.requirements = ["A C++ compiler", "libacl library"]
  s.files = ["README.rdoc", "COPYING.txt", Dir["ext/*.cpp"], Dir["ext/*.hpp"], Dir["ext/*.rb"], Dir["lib/**/*.rb"]].flatten
  s.extensions << "ext/extconf.rb"
  s.has_rdoc = true
  s.extra_rdoc_files = %w[README.rdoc]
  s.rdoc_options << "-t" << "libacl-ruby RDocs" << "-m" << "README.rdoc"
  #s.homepage = "http://hanmac.com/libacl-ruby
end
Rake::GemPackageTask.new(spec).define

Rake::RDocTask.new do |rd|
  rd.rdoc_files.include("COPYING.txt", "lib/**/*.rb", "ext/**/*.cpp", "ext/**/*.hpp", "**/*.rdoc")
  rd.title = "libacl-ruby RDocs"
  rd.main = "README.rdoc"
  rd.generator = "hanna" #Ignored if hanna-nouveau isn't installed
  rd.rdoc_dir = "doc"
end

Rake::TestTask.new("test") do |t|
  t.pattern = "test/test_*.rb"
  t.warning = true
end

desc "Compiles libacl-ruby, outputting ext/acl.so"
task :compile do
  cd "ext"
  ruby "extconf.rb"
  sh "make"
  cd ".."
end

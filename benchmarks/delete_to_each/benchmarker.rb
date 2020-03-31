require 'erb'
require 'ostruct'
require 'fileutils'
require 'json'

class Benchmarker
  include FileUtils

  def initialize(target, size)
    @target = target
    @size = size
  end

  def setup
    require 'puppet'
    config = File.join(@target, 'puppet.conf')
    Puppet.initialize_settings(['--config', config])
  end

  def run(args=nil)
    env = Puppet.lookup(:environments).get('benchmarking')
    node = Puppet::Node.new("testing", :environment => env)
    Puppet::Resource::Catalog.indirection.find("testing", :use_node => node)
  end

  def generate
    environment = File.join(@target, 'environments', 'benchmarking')
    templates = File.join('benchmarks', 'delete_to_each')

    mkdir_p(File.join(environment, 'modules'))
    mkdir_p(File.join(environment, 'manifests'))

    render(File.join(templates, 'site.pp.erb'),
           File.join(environment, 'manifests', 'site.pp'),
           :size => @size)

    module_base = File.join(environment, 'modules', 'dev')
    manifests = File.join(module_base, 'manifests')
    functions_3x = File.join(module_base, 'lib', 'puppet', 'parser', 'functions')
    functions_4x = File.join(module_base, 'functions')

    mkdir_p(manifests)
    mkdir_p(functions_3x)
    mkdir_p(functions_4x)

    File.open(File.join(module_base, 'metadata.json'), 'w') do |f|
      JSON.dump({
        "types" => [],
        "source" => "",
        "author" => "Delete to Each",
        "license" => "Apache 2.0",
        "version" => "1.0.0",
        "description" => "Delete 3x function to built-in typed each fn",
        "summary" => "Just this benchmark module, you know?",
        "dependencies" => [],
      }, f)
    end

    render(File.join(templates, 'dev', 'init.pp.erb'),
           File.join(manifests, 'init.pp'),
           :name => 'dev')

    render(File.join(templates, 'dev', 'delete.rb.erb'),
           File.join(functions_3x, 'delete.rb'), {})

    render(File.join(templates, 'dev', 'testing.pp.erb'),
           File.join(functions_4x, 'testing.pp'), {})

    render(File.join(templates, 'puppet.conf.erb'),
           File.join(@target, 'puppet.conf'),
           :location => @target)
  end

  def render(erb_file, output_file, bindings)
    site = ERB.new(File.read(erb_file))
    File.open(output_file, 'w') do |fh|
      fh.write(site.result(OpenStruct.new(bindings).instance_eval { binding }))
    end
  end
end

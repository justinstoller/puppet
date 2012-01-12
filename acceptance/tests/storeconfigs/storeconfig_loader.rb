store_config_dbs = ENV['storeconfigs_dbs'] || %w(sqlite3 mysql postgresql)
store_config_dbs.each do |db|
  eval(
    IO.read(
      File.join(File.dirname(__FILE__), 'store_config.setup')
    ), binding)

  eval(
    IO.read(
      File.join(File.dirname(__FILE__), 'realize_with_property.test')
    ), binding)

  eval(
    IO.read(
      File.join(File.dirname(__FILE__), 'realize_with_tags.test')
    ), binding)

  eval(
    IO.read(
      File.join(File.dirname(__FILE__), 'realize_with_meta_params.test')
    ), binding)

  eval(
    IO.read(
      File.join(File.dirname(__FILE__), 'store_config.teardown')
    ), binding)

end

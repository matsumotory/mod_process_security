MRuby::Build.new do |conf|

  toolchain :gcc
  conf.gembox 'full-core'
  conf.gem :mgem => 'mruby-mtest'
  conf.gem :mgem => 'mruby-httprequest'
  conf.gem :mgem => 'mruby-uname'

end

# frozen_string_literal: true

name 'volgactf-final'
description 'Installs and configures VolgaCTF Final'
version '1.5.0'

depends 'agit', '~> 0.1'
depends 'ruby_rbenv', '~> 4.0'
depends 'ngx', '~> 2.2'
depends 'tls', '~> 4.1'
depends 'nodejs', '~> 7.0'

gem 'htauth'

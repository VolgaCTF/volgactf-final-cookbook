# frozen_string_literal: true

resource_name :volgactf_final_master

property :root_dir, String, default: '/opt/volgactf/final'

property :user, String, required: true
property :user_home, String, required: true
property :group, String, required: true

property :repo_mode, String, equal_to: %w[https ssh], default: 'https'
property :run_mode, String, equal_to: %w[development production], default: 'production'

property :ruby_version, String, required: true

property :backend_repo_id, String, default: 'VolgaCTF/volgactf-final-backend'
property :backend_repo_revision, String, default: 'master'

property :frontend_repo_id, String, default: 'VolgaCTF/volgactf-final-frontend'
property :frontend_repo_revision, String, default: 'master'

property :stream_repo_id, String, default: 'VolgaCTF/volgactf-final-stream'
property :stream_repo_revision, String, default: 'master'

property :visualization_repo_id, String, default: 'VolgaCTF/volgactf-final-visualization'
property :visualization_repo_revision, String, default: 'master'

property :redis_host, String, required: true
property :redis_port, Integer, required: true
property :redis_password, [String, NilClass], default: nil

property :postgres_host, String, required: true
property :postgres_port, Integer, required: true
property :postgres_db, String, required: true
property :postgres_user, String, required: true
property :postgres_password, String, required: true

property :queue_redis_db, Integer, default: 1

property :stream_redis_db, Integer, default: 2
property :stream_redis_channel_namespace, String, default: 'volgactf.final'
property :stream_host, String, default: '127.0.0.1'
property :stream_port, Integer, default: 4000
property :stream_processes, Integer, default: 2
property :stream_max_listeners, Integer, default: 1024

property :internal_host, String, required: true
property :internal_port, Integer, default: 8000
property :internal_default_server, [TrueClass, FalseClass], default: true

property :public_fqdn, [String, Array], required: true
property :public_listen, [String, Array, NilClass], default: nil
property :public_secure, [TrueClass, FalseClass], default: true
property :public_default_server, [TrueClass, FalseClass], default: true
property :public_oscp_stapling, [TrueClass, FalseClass], default: true
property :public_hsts_max_age, Integer, default: 15_768_000

property :proxied_fqdn, [String, NilClass], default: nil
property :proxied_port, Integer, default: 9000
property :proxied_listen, [String, NilClass], default: nil
property :proxied_default_server, [TrueClass, FalseClass], default: true

property :auth_checker_username, String, required: true
property :auth_checker_password, String, required: true
property :auth_master_username, String, required: true
property :auth_master_password, String, required: true

property :flag_generator_secret, String, required: true
property :flag_sign_key_private, String, required: true
property :flag_sign_key_public, String, required: true
property :flag_wrap_prefix, String, default: 'VolgaCTF{'
property :flag_wrap_suffix, String, default: '}'

property :service_group_name, String, default: 'volgactf_final'

property :log_level, String, default: 'INFO'

property :web_host, String, default: '127.0.0.1'
property :web_port_start, Integer, default: 3001
property :web_processes, Integer, default: 2

property :queue_processes, Integer, default: 2

property :config, Hash, required: true

property :cleanup_upload_dir_enabled, [TrueClass, FalseClass], default: true
property :cleanup_upload_dir_cron, Hash, default: {
  'minute' => '*/30',
  'hour' => '*',
  'day' => '*',
  'month' => '*',
  'weekday' => '*'
}

property :access_log_options, String, default: 'combined'
property :error_log_options, String, default: 'error'

property :branding_cookbook, [String, NilClass], default: nil
property :branding_root, [String, NilClass], default: nil
property :branding_folders, Array, default: []
property :branding_files, Array, default: []

property :vlt_provider, Proc, default: -> { nil }
property :vlt_format, Integer, default: 2

default_action :install

action :install do
  directory new_resource.root_dir do
    owner new_resource.user
    group new_resource.group
    mode '0755'
    recursive true
    action :create
  end

  script_dir = ::File.join(new_resource.root_dir, 'script')

  directory script_dir do
    owner new_resource.user
    group new_resource.group
    mode '0755'
    recursive true
    action :create
  end

  media_dir = ::File.join(new_resource.root_dir, 'media')

  directory media_dir do
    owner new_resource.user
    group new_resource.group
    mode '0755'
    recursive true
    action :create
  end

  team_logo_dir = ::File.join(new_resource.root_dir, 'team_logo')

  directory team_logo_dir do
    owner new_resource.user
    group new_resource.group
    mode '0755'
    recursive true
    action :create
  end

  upload_dir = ::File.join(new_resource.root_dir, 'upload')

  directory upload_dir do
    owner new_resource.user
    group new_resource.group
    mode '0755'
    recursive true
    action :create
  end

  if new_resource.cleanup_upload_dir_enabled
    cleanup_upload_dir_script = ::File.join(script_dir, 'cleanup_upload_dir')

    template cleanup_upload_dir_script do
      cookbook 'volgactf-final'
      source 'script/cleanup_upload_dir.sh.erb'
      owner new_resource.user
      group new_resource.group
      variables(
        run_user: new_resource.user,
        upload_dir: upload_dir
      )
      mode '0755'
      action :create
    end

    cron 'volgactf_final_cleanup_upload_dir' do
      command cleanup_upload_dir_script
      minute new_resource.cleanup_upload_dir_cron['minute']
      hour new_resource.cleanup_upload_dir_cron['hour']
      day new_resource.cleanup_upload_dir_cron['day']
      month new_resource.cleanup_upload_dir_cron['month']
      weekday new_resource.cleanup_upload_dir_cron['weekday']
      action :create
    end
  end

  dump_db_script = ::File.join(script_dir, 'dump_main_db')

  template dump_db_script do
    cookbook 'volgactf-final'
    source 'script/dump_db.sh.erb'
    owner new_resource.user
    group new_resource.group
    mode '0775'
    variables(lazy do
      {
        pg_host: new_resource.postgres_host,
        pg_port: new_resource.postgres_port,
        pg_username: new_resource.postgres_user,
        pg_password: new_resource.postgres_password,
        pg_dbname: new_resource.postgres_db
      }
    end)
  end

  cleanup_script = ::File.join(script_dir, 'cleanup_logs')

  template cleanup_script do
    cookbook 'volgactf-final'
    source 'script/cleanup_logs.sh.erb'
    owner new_resource.user
    group new_resource.group
    mode '0775'
    variables(lazy do
      {
        dirs: [
          node.run_state['nginx']['log_dir']
        ]
      }
    end)
  end

  archive_script = ::File.join(script_dir, 'archive_logs')

  template archive_script do
    cookbook 'volgactf-final'
    source 'script/archive_logs.sh.erb'
    owner new_resource.user
    group new_resource.group
    mode '0775'
    variables(lazy do
      {
        dirs: [
          node.run_state['nginx']['log_dir']
        ]
      }
    end)
  end

  # backend

  backend_repo_url = if new_resource.repo_mode == 'ssh'
                       "git@github.com:#{new_resource.backend_repo_id}.git"
                     else
                       "https://github.com/#{new_resource.backend_repo_id}"
                     end

  backend_dir = ::File.join(new_resource.root_dir, 'backend')

  agit backend_dir do
    repository backend_repo_url
    branch new_resource.backend_repo_revision
    user new_resource.user
    group new_resource.group
    action :update
  end

  package 'libpq-dev'

  rbenv_script "Install dependencies at #{backend_dir}" do
    code 'bundle'
    rbenv_version new_resource.ruby_version
    cwd backend_dir
    user new_resource.user
    group new_resource.group
    action :run
  end

  env_dir = ::File.join(new_resource.root_dir, 'env')

  directory env_dir do
    owner new_resource.user
    group new_resource.group
    mode '0700'
    recursive true
    action :create
  end

  dotenv_file = ::File.join(backend_dir, '.env')

  template dotenv_file do
    cookbook 'volgactf-final'
    source 'dotenv.erb'
    user new_resource.user
    group new_resource.group
    mode '0600'
    variables(lazy do
      {
        env: {
          'REDIS_HOST' => new_resource.redis_host,
          'REDIS_PORT' => new_resource.redis_port,
          'REDIS_PASSWORD' => new_resource.redis_password,

          'PG_HOST' => new_resource.postgres_host,
          'PG_PORT' => new_resource.postgres_port,
          'PG_USERNAME' => new_resource.postgres_user,
          'PG_PASSWORD' => new_resource.postgres_password,
          'PG_DATABASE' => new_resource.postgres_db,

          'VOLGACTF_FINAL_STREAM_REDIS_DB' => new_resource.stream_redis_db,
          'VOLGACTF_FINAL_QUEUE_REDIS_DB' => new_resource.queue_redis_db,
          'VOLGACTF_FINAL_STREAM_REDIS_CHANNEL_NAMESPACE' => new_resource.stream_redis_channel_namespace,

          'VOLGACTF_FINAL_MASTER_HOST' => new_resource.internal_host,
          'VOLGACTF_FINAL_MASTER_PORT' => new_resource.internal_port,

          'VOLGACTF_FINAL_TEAM_LOGO_DIR' => team_logo_dir,
          'VOLGACTF_FINAL_UPLOAD_DIR' => upload_dir,

          'VOLGACTF_FINAL_AUTH_CHECKER_USERNAME' => new_resource.auth_checker_username,
          'VOLGACTF_FINAL_AUTH_CHECKER_PASSWORD' => new_resource.auth_checker_password,

          'VOLGACTF_FINAL_FLAG_GENERATOR_SECRET' => new_resource.flag_generator_secret,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PRIVATE' => new_resource.flag_sign_key_private,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PUBLIC' => new_resource.flag_sign_key_public,
          'VOLGACTF_FINAL_FLAG_WRAP_PREFIX' => new_resource.flag_wrap_prefix,
          'VOLGACTF_FINAL_FLAG_WRAP_SUFFIX' => new_resource.flag_wrap_suffix
        }
      }
    end)
    sensitive true
    action :create
  end

  template '/usr/local/bin/volgactf-final-cli' do
    cookbook 'volgactf-final'
    source 'volgactf-final-cli.sh.erb'
    user 'root'
    group node['root_group']
    mode '0755'
    variables(
      backend_dir: backend_dir
    )
    action :create
  end

  domain_dir = ::File.join(new_resource.root_dir, 'domain')

  directory domain_dir do
    owner new_resource.user
    group new_resource.group
    mode '0755'
    recursive true
    action :create
  end

  new_resource.config['domain_files'].each do |item|
    domain_filename = ::File.join(domain_dir, "#{item['name']}.rb")
    domain_vars = {
      services: item['services']
    }

    if item['type'] == 'competition_init'
      domain_vars.merge!(
        internal_networks: new_resource.config['internal_networks'],
        settings: new_resource.config['settings'],
        teams: new_resource.config['teams']
      )
    end

    template domain_filename do
      cookbook 'volgactf-final'
      source "domain/#{item['type']}.rb.erb"
      user new_resource.user
      group new_resource.group
      mode '0644'
      variables domain_vars
      action :create
    end
  end

  web_env_file_path = ::File.join(env_dir, 'web')

  template web_env_file_path do
    cookbook 'volgactf-final'
    source (node['platform'] == 'ubuntu' && node['platform_version'].to_f < 20.04) ? 'envfile.ubuntu-18.erb' : 'envfile.erb'
    owner new_resource.user
    group new_resource.group
    variables(lazy do
      {
        env: {
          'REDIS_HOST' => new_resource.redis_host,
          'REDIS_PORT' => new_resource.redis_port,
          'REDIS_PASSWORD' => new_resource.redis_password,

          'PG_HOST' => new_resource.postgres_host,
          'PG_PORT' => new_resource.postgres_port,
          'PG_USERNAME' => new_resource.postgres_user,
          'PG_PASSWORD' => new_resource.postgres_password,
          'PG_DATABASE' => new_resource.postgres_db,

          'VOLGACTF_FINAL_STREAM_REDIS_DB' => new_resource.stream_redis_db,
          'VOLGACTF_FINAL_QUEUE_REDIS_DB' => new_resource.queue_redis_db,
          'VOLGACTF_FINAL_STREAM_REDIS_CHANNEL_NAMESPACE' => new_resource.stream_redis_channel_namespace,

          'VOLGACTF_FINAL_MASTER_HOST' => new_resource.internal_host,
          'VOLGACTF_FINAL_MASTER_PORT' => new_resource.internal_port,

          'VOLGACTF_FINAL_TEAM_LOGO_DIR' => team_logo_dir,
          'VOLGACTF_FINAL_UPLOAD_DIR' => upload_dir,

          'VOLGACTF_FINAL_AUTH_CHECKER_USERNAME' => new_resource.auth_checker_username,
          'VOLGACTF_FINAL_AUTH_CHECKER_PASSWORD' => new_resource.auth_checker_password,

          'VOLGACTF_FINAL_AUTH_MASTER_USERNAME' => new_resource.auth_master_username,
          'VOLGACTF_FINAL_AUTH_MASTER_PASSWORD' => new_resource.auth_master_password,

          'VOLGACTF_FINAL_FLAG_GENERATOR_SECRET' => new_resource.flag_generator_secret,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PRIVATE' => new_resource.flag_sign_key_private,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PUBLIC' => new_resource.flag_sign_key_public,
          'VOLGACTF_FINAL_FLAG_WRAP_PREFIX' => new_resource.flag_wrap_prefix,
          'VOLGACTF_FINAL_FLAG_WRAP_SUFFIX' => new_resource.flag_wrap_suffix,

          'LOG_LEVEL' => new_resource.log_level,
          'STDOUT_SYNC' => new_resource.run_mode == 'development',
          'APP_ENV' => new_resource.run_mode
        }
      }
    end)
    mode '0600'
    sensitive true
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}.target]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_web@.service" do
    content(lazy do
      {
        Unit: {
          Description: 'VolgaCTF Final web server on port %I',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            'syslog.target'
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 5,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: backend_dir,
          EnvironmentFile: web_env_file_path,
          ExecStart: "#{::File.join(new_resource.user_home, '.rbenv', 'shims', 'bundle')} exec thin start -a #{new_resource.web_host} -p %I"
        }
      }
    end)
    action :create
  end

  queue_env_file_path = ::File.join(env_dir, 'queue')

  template queue_env_file_path do
    cookbook 'volgactf-final'
    source (node['platform'] == 'ubuntu' && node['platform_version'].to_f < 20.04) ? 'envfile.ubuntu-18.erb' : 'envfile.erb'
    owner new_resource.user
    group new_resource.group
    variables(lazy do
      {
        env: {
          'REDIS_HOST' => new_resource.redis_host,
          'REDIS_PORT' => new_resource.redis_port,
          'REDIS_PASSWORD' => new_resource.redis_password,

          'PG_HOST' => new_resource.postgres_host,
          'PG_PORT' => new_resource.postgres_port,
          'PG_USERNAME' => new_resource.postgres_user,
          'PG_PASSWORD' => new_resource.postgres_password,
          'PG_DATABASE' => new_resource.postgres_db,

          'VOLGACTF_FINAL_STREAM_REDIS_DB' => new_resource.stream_redis_db,
          'VOLGACTF_FINAL_QUEUE_REDIS_DB' => new_resource.queue_redis_db,
          'VOLGACTF_FINAL_STREAM_REDIS_CHANNEL_NAMESPACE' => new_resource.stream_redis_channel_namespace,

          'VOLGACTF_FINAL_MASTER_HOST' => new_resource.internal_host,
          'VOLGACTF_FINAL_MASTER_PORT' => new_resource.internal_port,

          'VOLGACTF_FINAL_TEAM_LOGO_DIR' => team_logo_dir,
          'VOLGACTF_FINAL_UPLOAD_DIR' => upload_dir,

          'VOLGACTF_FINAL_AUTH_CHECKER_USERNAME' => new_resource.auth_checker_username,
          'VOLGACTF_FINAL_AUTH_CHECKER_PASSWORD' => new_resource.auth_checker_password,

          'VOLGACTF_FINAL_FLAG_GENERATOR_SECRET' => new_resource.flag_generator_secret,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PRIVATE' => new_resource.flag_sign_key_private,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PUBLIC' => new_resource.flag_sign_key_public,
          'VOLGACTF_FINAL_FLAG_WRAP_PREFIX' => new_resource.flag_wrap_prefix,
          'VOLGACTF_FINAL_FLAG_WRAP_SUFFIX' => new_resource.flag_wrap_suffix,

          'LOG_LEVEL' => new_resource.log_level,
          'STDOUT_SYNC' => new_resource.run_mode == 'development'
        }
      }
    end)
    mode '0600'
    sensitive true
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}.target]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_queue@.service" do
    content(lazy do
      {
        Unit: {
          Description: 'VolgaCTF Final queue worker %I',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            'syslog.target'
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 5,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: backend_dir,
          EnvironmentFile: queue_env_file_path,
          ExecStart: "#{::File.join(new_resource.user_home, '.rbenv', 'shims', 'bundle')} exec sidekiq -r ./lib/queue/tasks.rb -i %I"
        }
      }
    end)
    action :create
  end

  scheduler_env_file_path = ::File.join(env_dir, 'scheduler')

  template scheduler_env_file_path do
    cookbook 'volgactf-final'
    source (node['platform'] == 'ubuntu' && node['platform_version'].to_f < 20.04) ? 'envfile.ubuntu-18.erb' : 'envfile.erb'
    owner new_resource.user
    group new_resource.group
    variables(lazy do
      {
        env: {
          'REDIS_HOST' => new_resource.redis_host,
          'REDIS_PORT' => new_resource.redis_port,
          'REDIS_PASSWORD' => new_resource.redis_password,

          'PG_HOST' => new_resource.postgres_host,
          'PG_PORT' => new_resource.postgres_port,
          'PG_USERNAME' => new_resource.postgres_user,
          'PG_PASSWORD' => new_resource.postgres_password,
          'PG_DATABASE' => new_resource.postgres_db,

          'VOLGACTF_FINAL_STREAM_REDIS_DB' => new_resource.stream_redis_db,
          'VOLGACTF_FINAL_QUEUE_REDIS_DB' => new_resource.queue_redis_db,
          'VOLGACTF_FINAL_STREAM_REDIS_CHANNEL_NAMESPACE' => new_resource.stream_redis_channel_namespace,

          'VOLGACTF_FINAL_MASTER_HOST' => new_resource.internal_host,
          'VOLGACTF_FINAL_MASTER_PORT' => new_resource.internal_port,

          'VOLGACTF_FINAL_TEAM_LOGO_DIR' => team_logo_dir,
          'VOLGACTF_FINAL_UPLOAD_DIR' => upload_dir,

          'VOLGACTF_FINAL_AUTH_CHECKER_USERNAME' => new_resource.auth_checker_username,
          'VOLGACTF_FINAL_AUTH_CHECKER_PASSWORD' => new_resource.auth_checker_password,

          'VOLGACTF_FINAL_FLAG_GENERATOR_SECRET' => new_resource.flag_generator_secret,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PRIVATE' => new_resource.flag_sign_key_private,
          'VOLGACTF_FINAL_FLAG_SIGN_KEY_PUBLIC' => new_resource.flag_sign_key_public,
          'VOLGACTF_FINAL_FLAG_WRAP_PREFIX' => new_resource.flag_wrap_prefix,
          'VOLGACTF_FINAL_FLAG_WRAP_SUFFIX' => new_resource.flag_wrap_suffix,

          'LOG_LEVEL' => new_resource.log_level,
          'STDOUT_SYNC' => new_resource.run_mode == 'development'
        }
      }
    end)
    mode '0600'
    sensitive true
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}.target]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_scheduler.service" do
    content(lazy do
      {
        Unit: {
          Description: 'VolgaCTF Final scheduler',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            'syslog.target'
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 10,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: backend_dir,
          EnvironmentFile: scheduler_env_file_path,
          ExecStart: "#{::File.join(new_resource.user_home, '.rbenv', 'shims', 'bundle')} exec ruby scheduler.rb"
        }
      }
    end)
    action :create
  end

  # frontend

  frontend_repo_url = if new_resource.repo_mode == 'ssh'
                        "git@github.com:#{new_resource.frontend_repo_id}.git"
                      else
                        "https://github.com/#{new_resource.frontend_repo_id}"
                      end

  frontend_dir = ::File.join(new_resource.root_dir, 'frontend')

  agit frontend_dir do
    repository frontend_repo_url
    branch new_resource.frontend_repo_revision
    user new_resource.user
    group new_resource.group
    action :update
  end

  npm_package 'volgactf-final-frontend' do
    path frontend_dir
    json true
    user new_resource.user
  end

  branding_root_path = nil
  unless new_resource.branding_cookbook.nil? || new_resource.branding_root.nil?
    branding_root_path = ::File.join(frontend_dir, new_resource.branding_root)

    directory branding_root_path do
      owner new_resource.user
      group new_resource.group
      mode '0755'
      recursive true
      action :create
    end

    new_resource.branding_folders.each do |x|
      directory ::File.join(branding_root_path, x) do
        owner new_resource.user
        group new_resource.group
        mode '0755'
        recursive true
        action :create
      end
    end

    new_resource.branding_files.each do |x|
      cookbook_file ::File.join(branding_root_path, x) do
        cookbook new_resource.branding_cookbook
        source ::File.join(new_resource.branding_root, x)
        owner new_resource.user
        group new_resource.group
        mode '0644'
        action :create
      end
    end
  end

  execute "build frontend at #{frontend_dir}" do
    command "npm run #{new_resource.run_mode == 'production' ? 'build' : 'devbuild'}"
    user new_resource.user
    cwd frontend_dir
    environment(
      'HOME' => new_resource.user_home,
      'BRANDING_ROOT_PATH' => branding_root_path.nil? ? ::File.join(frontend_dir, 'branding-default') : branding_root_path
    )
    action :run
  end

  # stream

  stream_repo_url = if new_resource.repo_mode == 'ssh'
                      "git@github.com:#{new_resource.stream_repo_id}.git"
                    else
                      "https://github.com/#{new_resource.stream_repo_id}"
                    end

  stream_dir = ::File.join(new_resource.root_dir, 'stream')

  agit stream_dir do
    repository stream_repo_url
    branch new_resource.stream_repo_revision
    user new_resource.user
    group new_resource.group
    action :update
  end

  npm_package 'volgactf-final-stream' do
    path stream_dir
    json true
    user new_resource.user
  end

  stream_config = {
    network: {
      internal: new_resource.config['internal_networks'],
      team: new_resource.config['teams'].values.map { |x| x['network'] }
    }
  }

  stream_config_file = ::File.join(stream_dir, 'config.json')

  file stream_config_file do
    owner new_resource.user
    group new_resource.group
    mode '0644'
    content ::JSON.pretty_generate(stream_config)
    action :create
  end

  stream_env_file_path = ::File.join(env_dir, 'stream')

  template stream_env_file_path do
    cookbook 'volgactf-final'
    source (node['platform'] == 'ubuntu' && node['platform_version'].to_f < 20.04) ? 'envfile.ubuntu-18.erb' : 'envfile.erb'
    owner new_resource.user
    group new_resource.group
    variables(lazy do
      {
        env: {
          'HOST' => new_resource.stream_host,
          'PORT' => new_resource.stream_port,
          'NUM_PROCESSES' => new_resource.stream_processes,

          'REDIS_HOST' => new_resource.redis_host,
          'REDIS_PORT' => new_resource.redis_port,
          'REDIS_PASSWORD' => new_resource.redis_password,

          'PG_HOST' => new_resource.postgres_host,
          'PG_PORT' => new_resource.postgres_port,
          'PG_USERNAME' => new_resource.postgres_user,
          'PG_PASSWORD' => new_resource.postgres_password,
          'PG_DATABASE' => new_resource.postgres_db,

          'VOLGACTF_FINAL_STREAM_REDIS_DB' => new_resource.stream_redis_db,
          'VOLGACTF_FINAL_STREAM_REDIS_CHANNEL_NAMESPACE' => new_resource.stream_redis_channel_namespace,
          'VOLGACTF_FINAL_STREAM_MAX_LISTENERS' => new_resource.stream_max_listeners,

          'LOG_LEVEL' => new_resource.log_level.downcase
        }
      }
    end)
    mode '0600'
    sensitive true
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}_stream.service]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_stream.service" do
    content(lazy do
      {
        Unit: {
          Description: 'VolgaCTF Final stream server',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            'syslog.target'
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 5,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: stream_dir,
          EnvironmentFile: stream_env_file_path,
          ExecStart: '/usr/local/bin/node server.js'
        }
      }
    end)
    action :create
  end

  systemd_unit "#{new_resource.service_group_name}.target" do
    content(lazy do
      {
        Unit: {
          Description: 'VolgaCTF Final',
          Wants: [
            "#{new_resource.service_group_name}_scheduler.service",
            "#{new_resource.service_group_name}_stream.service"
          ].concat(
            (1..new_resource.queue_processes).map { |x| "#{new_resource.service_group_name}_queue@#{x}.service" }
          ).concat(
            (0...new_resource.web_processes).map { |x| "#{new_resource.service_group_name}_web@#{x + new_resource.web_port_start}.service" }
          )
        },
        Install: {
          WantedBy: 'multi-user.target'
        }
      }
    end)
    action %i[create enable start]
  end

  # visualization

  visualization_repo_url = if new_resource.repo_mode == 'ssh'
                             "git@github.com:#{new_resource.visualization_repo_id}.git"
                           else
                             "https://github.com/#{new_resource.visualization_repo_id}"
                           end

  visualization_dir = ::File.join(new_resource.root_dir, 'visualization')

  agit visualization_dir do
    repository visualization_repo_url
    branch new_resource.visualization_repo_revision
    user new_resource.user
    group new_resource.group
    action :update
  end

  # other

  nginx_dir = ::File.join(new_resource.root_dir, 'nginx')

  directory nginx_dir do
    owner(lazy { node.run_state['nginx']['user'] })
    group(lazy { node.run_state['nginx']['group'] })
    mode '0700'
    recursive true
    action :create
  end

  nginx_conf 'volgactf-final-ratelimit' do
    cookbook 'volgactf-final'
    template 'nginx/ratelimit.conf.erb'
    variables(
      team_networks: new_resource.config['teams'].values.map { |x| x['network'] },
      flag_submit_req_limit_rate: new_resource.config['api_req_limits']['flag_submit']['rate'],
      flag_info_req_limit_rate: new_resource.config['api_req_limits']['flag_info']['rate'],
      service_status_req_limit_rate: new_resource.config['api_req_limits']['service_status']['rate']
    )
    action :create
  end

  helper_js_nginx = ::File.join(nginx_dir, 'volgactf-final-helper.js')

  service 'nginx' do
    action :nothing
  end

  cookbook_file helper_js_nginx do
    cookbook 'volgactf-final'
    source 'volgactf-final-helper.js'
    owner(lazy { node.run_state['nginx']['user'] })
    group(lazy { node.run_state['nginx']['group'] })
    action :create
    notifies :restart, 'service[nginx]', :delayed
  end

  upstream_web_name = 'volgactf-final-web'

  nginx_conf 'volgactf-final-upstream' do
    cookbook 'volgactf-final'
    template 'nginx/upstream.conf.erb'
    variables(
      upstream_web: upstream_web_name,
      web_processes: new_resource.web_processes,
      web_host: new_resource.web_host,
      web_port_start: new_resource.web_port_start,
      upstream_stream: 'volgactf-final-stream',
      stream_host: new_resource.stream_host,
      stream_port: new_resource.stream_port
    )
    action :create
  end

  nginx_conf 'volgactf-final-js' do
    cookbook 'volgactf-final'
    template 'nginx/js.conf.erb'
    variables(
      helper_js_nginx: helper_js_nginx
    )
    action :create
  end

  public_listen = nil
  unless new_resource.public_listen.nil?
    public_listen = new_resource.public_listen.is_a?(Array) ? new_resource.public_listen : [new_resource.public_listen]
  end

  public_fqdn_list = new_resource.public_fqdn.is_a?(Array) ? new_resource.public_fqdn : [new_resource.public_fqdn]

  ngx_vhost_variables = {
    fqdn_list: public_fqdn_list,
    port: 80,
    listen: public_listen,
    default_server: new_resource.public_default_server,
    secure: new_resource.public_secure,
    secure_port: 443,
    proxied: false,
    access_log_options: new_resource.access_log_options,
    error_log_options: new_resource.error_log_options,
    frontend_dir: frontend_dir,
    visualization_dir: visualization_dir,
    media_dir: media_dir,
    upstream_web: upstream_web_name,
    upstream_stream: 'volgactf-final-stream',
    internal_networks: new_resource.config['internal_networks'],
    team_networks: new_resource.config['teams'].values.map { |x| x['network'] },
    competition_title: new_resource.config['competition']['title'],
    flag_info_req_limit_burst: new_resource.config['api_req_limits']['flag_info']['burst'],
    flag_info_req_limit_nodelay: new_resource.config['api_req_limits']['flag_info']['nodelay'],
    flag_submit_req_limit_burst: new_resource.config['api_req_limits']['flag_submit']['burst'],
    flag_submit_req_limit_nodelay: new_resource.config['api_req_limits']['flag_submit']['nodelay'],
    service_status_req_limit_burst: new_resource.config['api_req_limits']['service_status']['burst'],
    service_status_req_limit_nodelay: new_resource.config['api_req_limits']['service_status']['nodelay']
  }

  if new_resource.public_secure
    tls_rsa_certificate public_fqdn_list[0] do
      vlt_provider new_resource.vlt_provider
      vlt_format new_resource.vlt_format
      action :deploy
    end

    tls = ::ChefCookbook::TLS.new(node, vlt_provider: new_resource.vlt_provider, vlt_format: new_resource.vlt_format)

    ngx_vhost_variables.merge!(
      certificate_entries: [
        tls.rsa_certificate_entry(public_fqdn_list[0])
      ],
      hsts_max_age: new_resource.public_hsts_max_age,
      oscp_stapling: new_resource.public_oscp_stapling
    )

    if tls.has_ec_certificate?(public_fqdn_list[0])
      tls_ec_certificate public_fqdn_list[0] do
        vlt_provider new_resource.vlt_provider
        vlt_format new_resource.vlt_format
        action :deploy
      end

      ngx_vhost_variables[:certificate_entries] << tls.ec_certificate_entry(public_fqdn_list[0])
    end
  end

  nginx_vhost 'volgactf-final' do
    cookbook 'volgactf-final'
    template 'nginx/master.vhost.conf.erb'
    variables(lazy do
      ngx_vhost_variables.merge(
        access_log: ::File.join(
          node.run_state['nginx']['log_dir'],
          'volgactf-final_access.log'
        ),
        error_log: ::File.join(
          node.run_state['nginx']['log_dir'],
          'volgactf-final_error.log'
        )
      )
    end)
    action :enable
  end

  unless new_resource.proxied_fqdn.nil?
    nginx_vhost 'volgactf-final.proxied' do
      cookbook 'volgactf-final'
      template 'nginx/master.vhost.conf.erb'
      variables(lazy do
        ngx_vhost_variables.merge(
          fqdn_list: [new_resource.proxied_fqdn],
          listen: new_resource.proxied_listen.nil? ? nil : [new_resource.proxied_listen],
          port: new_resource.proxied_port,
          default_server: new_resource.proxied_default_server,
          secure: false,
          proxied: true,
          access_log: ::File.join(
            node.run_state['nginx']['log_dir'],
            'volgactf-final.proxied_access.log'
          ),
          error_log: ::File.join(
            node.run_state['nginx']['log_dir'],
            'volgactf-final.proxied_error.log'
          )
        )
      end)
      action :enable
    end
  end

  nginx_vhost 'volgactf-final.internal' do
    cookbook 'volgactf-final'
    template 'nginx/master.internal.vhost.conf.erb'
    variables(lazy do
      {
        host: new_resource.internal_host,
        port: new_resource.internal_port,
        default_server: new_resource.internal_default_server,
        access_log: ::File.join(node.run_state['nginx']['log_dir'], 'volgactf-final.internal_access.log'),
        access_log_options: new_resource.access_log_options,
        error_log: ::File.join(node.run_state['nginx']['log_dir'], 'volgactf-final.internal_error.log'),
        error_log_options: new_resource.error_log_options,
        upstream_web: upstream_web_name,
        internal_networks: new_resource.config['internal_networks']
      }
    end)
    action :enable
  end
end

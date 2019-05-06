resource_name :volgactf_final_checker

property :root_dir, String, default: '/opt/volgactf/final'

property :docker_image_repo, String, required: true
property :docker_image_tag, String, required: true
property :docker_network_name, String, required: true
property :docker_network_gateway, String, required: true

property :auth_checker_username, String, required: true
property :auth_checker_password, String, required: true
property :auth_master_username, String, required: true
property :auth_master_password, String, required: true

property :flag_sign_key_public, String, required: true
property :flag_wrap_prefix, String, default: 'VolgaCTF{'
property :flag_wrap_suffix, String, default: '}'

property :upstream_host, String, default: '127.0.0.1'
property :upstream_port_start, Integer, default: 8001
property :upstream_processes, Integer, default: 2

property :fqdn, String, required: true

property :environment, Hash, default: {}

property :access_log_options, String, default: 'combined'
property :error_log_options, String, default: 'error'

property :service_group_name, String, default: 'volgactf_final'

default_action :install

action :install do
  checker_dir = ::File.join(new_resource.root_dir, new_resource.name)

  directory checker_dir do
    mode 0o755
    recursive true
    action :create
  end

  docker_image new_resource.name do
    repo new_resource.docker_image_repo
    tag new_resource.docker_image_tag
    action :pull
  end

  dotenv_file = ::File.join(checker_dir, 'env')

  template dotenv_file do
    cookbook 'volgactf-final'
    source 'dotenv.erb'
    mode 0o644
    variables(
      env: new_resource.environment.merge({
        'THEMIS_FINALS_AUTH_MASTER_USERNAME' => new_resource.auth_master_username,
        'THEMIS_FINALS_AUTH_MASTER_PASSWORD' => new_resource.auth_master_password,
        'THEMIS_FINALS_AUTH_CHECKER_USERNAME' => new_resource.auth_checker_username,
        'THEMIS_FINALS_AUTH_CHECKER_PASSWORD' => new_resource.auth_checker_password,
        'THEMIS_FINALS_FLAG_SIGN_KEY_PUBLIC' => new_resource.flag_sign_key_public,
        'THEMIS_FINALS_FLAG_WRAP_PREFIX' => new_resource.flag_wrap_prefix,
        'THEMIS_FINALS_FLAG_WRAP_SUFFIX' => new_resource.flag_wrap_suffix
      })
    )
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}_#{new_resource.name}.target]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_#{new_resource.name}@.service" do
    content({
      Unit: {
        Description: "#{new_resource.name} container on port %i",
        PartOf: "#{new_resource.service_group_name}_#{new_resource.name}.target",
        After: [
          'network.target',
          'syslog.target',
          'docker.service'
        ]
      },
      Service: {
        Restart: 'always',
        RestartSec: 5,
        ExecStartPre: %Q(/bin/sh -c "/usr/bin/docker rm -f #{new_resource.name}-%i 2> /dev/null || /bin/true"),
        ExecStart: "/usr/bin/docker run --rm -a STDIN -a STDOUT -a STDERR -p #{new_resource.upstream_host}:%i:80 --network #{new_resource.docker_network_name} --dns #{new_resource.docker_network_gateway} --env-file #{dotenv_file} --name #{new_resource.name}-%i #{new_resource.docker_image_repo}:#{new_resource.docker_image_tag}",
        ExecStop: "/usr/bin/docker stop #{new_resource.name}-%i"
      },
      Install: {
        WantedBy: 'multi-user.target'
      }
    })
    action :create
  end

  systemd_unit "#{new_resource.service_group_name}_#{new_resource.name}.target" do
    content(lazy {
      {
        Unit: {
          Description: "VolgaCTF Final #{new_resource.name} cluster",
          Wants: (0...new_resource.upstream_processes).map { |x| "#{new_resource.service_group_name}_#{new_resource.name}@#{x + new_resource.upstream_port_start}.service" }
        },
        Install: {
          WantedBy: 'multi-user.target'
        }
      }
    })
    action %i[create enable start]
  end

  nginx_vhost "volgactf-final-#{new_resource.name}" do
    cookbook 'volgactf-final'
    template 'nginx/checker.vhost.conf.erb'
    variables(lazy {
      {
        fqdn: new_resource.fqdn,
        name: new_resource.name,
        access_log: ::File.join(node.run_state['nginx']['log_dir'], 'volgactf-final_access.log'),
        access_log_options: new_resource.access_log_options,
        error_log: ::File.join(node.run_state['nginx']['log_dir'], 'volgactf-final_error.log'),
        error_log_options: new_resource.error_log_options,
        upstream_host: new_resource.upstream_host,
        upstream_processes: new_resource.upstream_processes,
        upstream_port_start: new_resource.upstream_port_start
      }
    })
    action :enable
  end
end

# frozen_string_literal: true

resource_name :volgactf_final_proxy

property :fqdn, String, name_property: true
property :upstream_host, String, required: true
property :upstream_port, Integer, required: true
property :secure, [TrueClass, FalseClass], default: true
property :hsts_max_age, Integer, default: 15_768_000
property :ocsp_stapling, [TrueClass, FalseClass], default: true
property :resolvers, Array, default: %w[8.8.8.8 1.1.1.1 8.8.4.4 1.0.0.1]
property :resolver_valid, Integer, default: 600
property :resolver_timeout, Integer, default: 10
property :listen_ipv6, [true, false], default: false
property :default_server, [true, false], default: false
property :access_log_options, String, default: 'combined'
property :error_log_options, String, default: 'error'

property :vlt_provider, Proc, default: -> { nil }
property :vlt_format, Integer, default: 2

default_action :install

action :install do
  ngx_vhost_variables = {
    fqdn: new_resource.fqdn,
    listen_ipv6: new_resource.listen_ipv6,
    default_server: new_resource.default_server,
    secure: new_resource.secure,
    upstream_host: new_resource.upstream_host,
    upstream_port: new_resource.upstream_port,
    access_log_options: new_resource.access_log_options,
    error_log_options: new_resource.error_log_options
  }

  if new_resource.secure
    tls_rsa_certificate new_resource.fqdn do
      vlt_provider new_resource.vlt_provider
      vlt_format new_resource.vlt_format
      action :deploy
    end

    tls = ::ChefCookbook::TLS.new(node, vlt_provider: new_resource.vlt_provider, vlt_format: new_resource.vlt_format)

    ngx_vhost_variables.merge!(
      certificate_entries: [
        tls.rsa_certificate_entry(new_resource.fqdn)
      ],
      hsts_max_age: new_resource.hsts_max_age,
      ocsp_stapling: new_resource.ocsp_stapling,
      resolvers: new_resource.resolvers,
      resolver_valid: new_resource.resolver_valid,
      resolver_timeout: new_resource.resolver_timeout
    )

    if tls.has_ec_certificate?(new_resource.fqdn)
      tls_ec_certificate new_resource.fqdn do
        vlt_provider new_resource.vlt_provider
        vlt_format new_resource.vlt_format
        action :deploy
      end

      ngx_vhost_variables[:certificate_entries] << tls.ec_certificate_entry(new_resource.fqdn)
    end
  end

  nginx_vhost new_resource.fqdn do
    cookbook 'volgactf-final'
    template 'nginx/proxy.vhost.conf.erb'
    variables(lazy do
      ngx_vhost_variables.merge(
        access_log: ::File.join(
          node.run_state['nginx']['log_dir'],
          "#{new_resource.fqdn}_access.log"
        ),
        error_log: ::File.join(
          node.run_state['nginx']['log_dir'],
          "#{new_resource.fqdn}_error.log"
        )
      )
    end)
    action :enable
  end
end

resource_name :volgactf_final_proxy

property :fqdn, String, name_property: true
property :ipv4_address, String, required: true
property :secure, [TrueClass, FalseClass], default: true
property :hsts_max_age, Integer, default: 15_768_000
property :oscp_stapling, [TrueClass, FalseClass], default: true
property :resolvers, Array, default: %w(8.8.8.8 1.1.1.1 8.8.4.4 1.0.0.1)
property :resolver_valid, Integer, default: 600
property :resolver_timeout, Integer, default: 10
property :access_log_options, String, default: 'combined'
property :error_log_options, String, default: 'error'

default_action :create

action :create do
  ngx_vhost_variables = {
    fqdn: new_resource.fqdn,
    secure: new_resource.secure,
    ipv4_address: new_resource.ipv4_address,
    access_log_options: new_resource.access_log_options,
    error_log_options: new_resource.error_log_options
  }

  if new_resource.secure
    tls_rsa_certificate new_resource.fqdn do
      action :deploy
    end

    tls = ::ChefCookbook::TLS.new(node)

    ngx_vhost_variables.merge!(
      certificate_entries: [
        tls.rsa_certificate_entry(new_resource.fqdn)
      ],
      hsts_max_age: new_resource.hsts_max_age,
      oscp_stapling: new_resource.oscp_stapling,
      resolvers: new_resource.resolvers,
      resolver_valid: new_resource.resolver_valid,
      resolver_timeout: new_resource.resolver_timeout
    )

    if tls.has_ec_certificate?(new_resource.fqdn)
      tls_ec_certificate new_resource.fqdn do
        action :deploy
      end

      ngx_vhost_variables[:certificate_entries] << tls.ec_certificate_entry(new_resource.fqdn)
    end
  end

  nginx_vhost new_resource.fqdn do
    cookbook 'volgactf-final'
    template 'nginx/proxy.vhost.conf.erb'
    variables(lazy {
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
    })
    action :enable
  end
end

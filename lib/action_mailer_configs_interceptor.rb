# frozen_string_literal: true

module ActionMailerConfigsInterceptor
  OPEN_TIMEOUT = ENV.fetch('SMTP_OPEN_TIMEOUT', '15').to_i
  READ_TIMEOUT = ENV.fetch('SMTP_READ_TIMEOUT', '25').to_i

  module_function

  def delivering_email(message)
    return message unless Rails.env.production?

    if Docuseal.demo?
      message.delivery_method(:test)

      return message
    end

    account_id = message.instance_variable_get(:@message_metadata)&.dig('account_id')

    email_configs =
      if account_id
        EncryptedConfig.find_by(account_id:, key: EncryptedConfig::EMAIL_SMTP_KEY)
      elsif !Docuseal.multitenant?
        EncryptedConfig.order(:account_id).find_by(key: EncryptedConfig::EMAIL_SMTP_KEY)
      end

    if email_configs&.value&.dig('host').present?
      apply_account_smtp!(message, email_configs)
    elsif global_smtp_configured?
      apply_global_smtp!(message)
    elsif !Docuseal.multitenant? || account_id
      message.delivery_method(:test)
    end

    message
  end

  def global_smtp_configured?
    ENV['SMTP_ADDRESS'].present?
  end

  def apply_global_smtp!(message)
    message.delivery_method(:smtp, build_global_smtp_hash)

    from = ENV.fetch('SMTP_FROM').to_s.split(',').map(&:strip).reject(&:blank?).sample

    message.from = from if from.present? && from.match?(User::FULL_EMAIL_REGEXP)
  end

  def apply_account_smtp!(message, email_configs)
    message.delivery_method(:smtp, build_smtp_configs_hash(email_configs))

    message.from = %("#{email_configs.account.name.to_s.delete('"')}" <#{email_configs.value['from_email']}>)
  end

  def build_global_smtp_hash
    {
      address: ENV.fetch('SMTP_ADDRESS'),
      port: ENV.fetch('SMTP_PORT', 587).to_i,
      domain: ENV['SMTP_DOMAIN'].presence,
      user_name: ENV['SMTP_USERNAME'].presence,
      password: ENV['SMTP_PASSWORD'].presence,
      authentication: ENV['SMTP_PASSWORD'].present? ? ENV.fetch('SMTP_AUTHENTICATION', 'plain') : nil,
      enable_starttls_auto: ENV['SMTP_ENABLE_STARTTLS_AUTO'] != 'false',
      open_timeout: OPEN_TIMEOUT,
      read_timeout: READ_TIMEOUT
    }.compact
  end

  def build_smtp_configs_hash(email_configs)
    value = email_configs.value

    {
      user_name: value['username'],
      password: value['password'],
      address: value['host'],
      port: value['port'],
      domain: value['domain'],
      openssl_verify_mode: value['security'] == 'noverify' ? OpenSSL::SSL::VERIFY_NONE : nil,
      authentication: value['password'].present? ? value.fetch('authentication', 'plain') : nil,
      enable_starttls_auto: value['security'] != 'tls',
      open_timeout: OPEN_TIMEOUT,
      read_timeout: READ_TIMEOUT,
      ssl: value['security'] == 'ssl',
      tls: value['security'] == 'tls' || (value['security'].blank? && value['port'].to_s == '465')
    }.compact_blank
  end
end

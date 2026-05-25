# frozen_string_literal: true

class SsoLoginController < ApplicationController
    skip_before_action :maybe_redirect_to_setup
    skip_before_action :authenticate_user!
    skip_authorization_check
  
    # SSO JWT secret key for decoding tokens
    SSO_JWT_SECRET = '6a5a4fa4733123c991256f5b0f2221fbe8f7b4c210f74fba621b44c9d5e9f8b6'.freeze
  
    def login
      token = params[:token]

      unless token.present?
        return redirect_to root_path, alert: 'Missing authentication token'
      end

      begin
        # Decode JWT token using the SSO secret key
        decoded_token = decode_sso_jwt(token)
        
        email = decoded_token['email']&.strip&.downcase
        first_name = decoded_token['first_name']
        last_name = decoded_token['last_name']
        user_type = normalize_user_role(decoded_token['user_type'])
        template_id = decoded_token['template_id']
        # Check for facility_id/facility_name first (new payload format), then fallback to company_id/company_name
        company_id = decoded_token['facility_id'] || decoded_token['company_id'] || decoded_token['account_id'] || decoded_token['organization_id']
        company_name = decoded_token['facility_name'] || decoded_token['company_name'] || decoded_token['account_name'] || decoded_token['organization_name']
        company_name = company_name&.strip

        Rails.logger.info("SSO Login - Email: #{email}, Company ID: #{company_id}, Company Name: #{company_name}")
        Rails.logger.info("JWT Payload keys: #{decoded_token.keys.inspect}")
        Rails.logger.info("Full JWT Payload: #{decoded_token.inspect}")

        unless email.present?
          return redirect_to root_path, alert: 'Invalid token: email missing'
        end

        # Find or create user with company/account
        user = find_or_create_user(email, first_name, last_name, company_id, company_name, user_type)

        if user
          # Sign in the user
          sign_in(user)

          # Redirect to template preview if template_id is present
          if template_id.present?
            Rails.logger.error("It is here actually. TemplateID: #{template_id}")
            return redirect_to template_preview_path(template_id)
          end

          # Redirect to dashboard
          redirect_to root_path, notice: 'Signed in successfully'
        else
          redirect_to root_path, alert: 'Unable to sign in'
        end
      rescue JWT::DecodeError, JWT::ExpiredSignature => e
        Rails.logger.error("SSO JWT decode error: #{e.message}")
        redirect_to root_path, alert: 'Invalid or expired authentication token'
      rescue StandardError => e
        Rails.logger.error("SSO login error: #{e.message}")
        Rails.logger.error(e.backtrace.join("\n"))
        redirect_to root_path, alert: 'An error occurred during sign in'
      end
    end
  
    private
  
    def decode_sso_jwt(token)
      # Decode JWT with the SSO secret key
      decoded = JWT.decode(token, SSO_JWT_SECRET, true, { algorithm: 'HS256' })
      decoded[0] # Return the payload
    end
  
    def find_or_create_user(email, first_name, last_name, company_id = nil, company_name = nil, user_type = nil)
      # Try to find existing user by email (email is unique globally)
      user = User.find_by(email: email)
  
      if user
        # User exists - keep them in their current account to preserve data visibility.
        account = user.account
        sync_account_tpms_admin_id!(account, company_id)
        Rails.logger.info("User #{email} exists in account #{account.id} (#{account.name}). Keeping in existing account.")

        # Update user attributes from SSO
        # Names are only updated if blank to preserve manual changes
        # Role is updated from SSO payload
        update_attrs = {}
        if user.first_name.blank? && first_name.present?
          update_attrs[:first_name] = first_name
        end
        if user.last_name.blank? && last_name.present?
          update_attrs[:last_name] = last_name
        end
        if user_type.present? && user.role != user_type
          update_attrs[:role] = user_type
          Rails.logger.info("Updating user #{user.email} role to #{user_type} from SSO")
        end
        
        if update_attrs.any? && !user.update(update_attrs)
          Rails.logger.error("Failed to update user #{email} from SSO: #{user.errors.full_messages.join(', ')}")
          return nil
        end
  
        return user
      end
  
      # User doesn't exist - create account based on company_id and create new user
      account = find_or_create_account_by_company(company_id, company_name)
      sync_account_tpms_admin_id!(account, company_id)
  
      # Generate a random password for the new user
      password = SecureRandom.hex(16)
  
      # Create the new user
      user = account.users.build(
        email: email,
        first_name: first_name || '',
        last_name: last_name || '',
        password: password,
        role: user_type.presence || User::ADMIN_ROLE
      )
  
      if user.save
        user
      else
        Rails.logger.error("Failed to create user: #{user.errors.full_messages.join(', ')}")
        nil
      end
    end
  
    def find_or_create_account_by_company(company_id = nil, company_name = nil)
      Rails.logger.info("Finding or creating account - company_id: #{company_id}, company_name: #{company_name}")

      # If company_id is provided, try to find account by ID or UUID
      if company_id.present?
        company_id_str = company_id.to_s

        # Preferred lookup for SSO external mapping: tpms_admin_id
        account = Account.active.find_by(tpms_admin_id: company_id_str)
        if account
          Rails.logger.info("Found existing account: #{account.id} (#{account.name}) for tpms_admin_id: #{company_id_str}")
          return account
        end

        # Try to find by ID first (handle both string and integer)
        company_id_int = company_id.to_i
        account = Account.active.find_by(id: company_id_int) if company_id_int > 0
        
        # If not found by ID, try to find by UUID
        account ||= Account.active.find_by(uuid: company_id_str) if account.nil?
        
        if account
          # Keep external facility mapping in sync
          if account.tpms_admin_id != company_id_str
            account.update(tpms_admin_id: company_id_str)
            Rails.logger.info("Updated account #{account.id} tpms_admin_id to #{company_id_str}")
          end
          Rails.logger.info("Found existing account: #{account.id} (#{account.name}) for company_id: #{company_id}")
          return account
        else
          # Fallback: avoid duplicate accounts if an account with the same name already exists.
          if company_name.present?
            account_by_name = Account.active.find_by(name: company_name)
            if account_by_name
              account_by_name.update(tpms_admin_id: company_id_str) if account_by_name.tpms_admin_id != company_id_str
              Rails.logger.info("Matched account by name: #{account_by_name.id} (#{account_by_name.name}) and synced tpms_admin_id to #{company_id_str}")
              return account_by_name
            end
          end

          Rails.logger.info("Account not found for company_id: #{company_id}, creating new account")
          # Account not found - create new one with company_id reference
          account_name = company_name.present? ? company_name : "Company #{company_id}"
          account = Account.create!(
            name: account_name,
            tpms_admin_id: company_id_str,
            timezone: 'UTC',
            locale: 'en-US'
          )
          initialize_account_configs(account)
          Rails.logger.info("Created new account: #{account.id} (#{account.name}) for company_id: #{company_id}")
          return account
        end
      end
  
      # If company_name is provided, try to find by name
      if company_name.present?
        account = Account.active.find_by(name: company_name)
        if account
          if company_id.present? && account.tpms_admin_id != company_id.to_s
            account.update(tpms_admin_id: company_id.to_s)
            Rails.logger.info("Updated account #{account.id} tpms_admin_id to #{company_id}")
          end
          Rails.logger.info("Found existing account: #{account.id} (#{account.name}) for company_name: #{company_name}")
          return account
        else
          Rails.logger.info("Account not found for company_name: #{company_name}, creating new account")
          # Account not found - create new one
          account = Account.create!(
            name: company_name,
            tpms_admin_id: company_id.presence&.to_s,
            timezone: 'UTC',
            locale: 'en-US'
          )
          initialize_account_configs(account)
          Rails.logger.info("Created new account: #{account.id} (#{account.name}) for company_name: #{company_name}")
          return account
        end
      end
  
      # If no company_id or company_name provided
      # Check if this is the first user (no accounts exist)
      if Account.active.count.zero?
        Rails.logger.info("No accounts exist, creating first default account")
        account = create_default_account('Default Account')
        return account
      end
  
      # If no company_id/name provided and accounts exist, create a new account with unique name
      # This should not happen in production if company_id is always provided
      account_name = "Company #{SecureRandom.hex(4)}"
      Rails.logger.warn("No company_id or company_name provided, creating account with random name: #{account_name}")
      account = Account.create!(
        name: account_name,
        timezone: 'UTC',
        locale: 'en-US'
      )
      initialize_account_configs(account)
      Rails.logger.info("Created new account: #{account.id} (#{account.name}) without company identifier")
      account
    end

    def sync_account_tpms_admin_id!(account, company_id)
      return if account.blank? || company_id.blank?

      company_id_str = company_id.to_s
      return if account.tpms_admin_id == company_id_str

      account.update_column(:tpms_admin_id, company_id_str)
      Rails.logger.info("Synced account #{account.id} tpms_admin_id to #{company_id_str}")
    rescue StandardError => e
      Rails.logger.error("Failed to sync tpms_admin_id for account #{account&.id}: #{e.message}")
    end
  
    def create_default_account(name = 'Default Account')
      account = Account.create!(
        name: name,
        timezone: 'UTC',
        locale: 'en-US'
      )
  
      initialize_account_configs(account)
  
      account
    end
  
    def initialize_account_configs(account)
      # Create encrypted configs if needed
      if EncryptedConfig.table_exists?
        app_url_host =
          begin
            Docuseal.default_url_options[:host]
          rescue ActiveRecord::Encryption::Errors::Decryption, OpenSSL::Cipher::CipherError => e
            Rails.logger.warn("Could not read default app URL from encrypted config: #{e.class} - #{e.message}. Falling back to request host.")
            nil
          end

        app_url = app_url_host || request.host
        app_url = "https://#{app_url}" unless app_url.start_with?('http')
  
        encrypted_configs = [
          { key: EncryptedConfig::APP_URL_KEY, value: app_url }
        ]
  
        # Only add ESIGN certs if GenerateCertificate is available
        begin
          encrypted_configs << {
            key: EncryptedConfig::ESIGN_CERTS_KEY,
            value: GenerateCertificate.call.transform_values(&:to_pem)
          }
        rescue NameError, StandardError => e
          Rails.logger.warn("Could not generate ESIGN certificates: #{e.message}")
        end
  
        account.encrypted_configs.create!(encrypted_configs) if encrypted_configs.any?
      end
  
      # Create account configs if needed
      if AccountConfig.table_exists? && SearchEntry.table_exists?
        account.account_configs.create!(key: :fulltext_search, value: true)
      end
    end

    def normalize_user_role(user_type)
      role = user_type.to_s.downcase.strip
      return User::ADMIN_ROLE if role.blank?
      return role if User::ROLES.include?(role)

      Rails.logger.warn("Unsupported SSO user_type '#{user_type}' received. Falling back to #{User::ADMIN_ROLE}.")

      User::ADMIN_ROLE
    end
  end

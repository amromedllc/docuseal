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
        
        email = decoded_token['email']&.downcase
        first_name = decoded_token['first_name']
        last_name = decoded_token['last_name']
        # Check for facility_id/facility_name first (new payload format), then fallback to company_id/company_name
        company_id = decoded_token['facility_id'] || decoded_token['company_id'] || decoded_token['account_id'] || decoded_token['organization_id']
        company_name = decoded_token['facility_name'] || decoded_token['company_name'] || decoded_token['account_name'] || decoded_token['organization_name']
  
        Rails.logger.info("SSO Login - Email: #{email}, Company ID: #{company_id}, Company Name: #{company_name}")
        Rails.logger.info("JWT Payload keys: #{decoded_token.keys.inspect}")
        Rails.logger.info("Full JWT Payload: #{decoded_token.inspect}")
  
        unless email.present?
          return redirect_to root_path, alert: 'Invalid token: email missing'
        end
  
        # Find or create user with company/account
        user = find_or_create_user(email, first_name, last_name, company_id, company_name)
  
        if user
          # Sign in the user
          sign_in(user)
          
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
  
    def find_or_create_user(email, first_name, last_name, company_id = nil, company_name = nil)
      # Try to find existing user by email (email is unique globally)
      user = User.find_by(email: email)
  
      if user
        # User exists - KEEP them in their existing account
        # Don't move users between accounts to preserve their data (files, templates, etc.)
        account = user.account
        Rails.logger.info("User #{email} exists in account #{account.id} (#{account.name}). Keeping in existing account.")
        
        # Log if company_id points to a different account (for debugging)
        if company_id.present? || company_name.present?
          expected_account = find_or_create_account_by_company(company_id, company_name)
          if expected_account && user.account_id != expected_account.id
            Rails.logger.warn("User #{email} is in account #{user.account_id} but company_id #{company_id} points to account #{expected_account.id}. User kept in existing account to preserve data.")
          end
        end
  
        # Update user info if provided and different
        update_attrs = {}
        update_attrs[:first_name] = first_name if first_name.present? && user.first_name != first_name
        update_attrs[:last_name] = last_name if last_name.present? && user.last_name != last_name
        
        user.update(update_attrs) if update_attrs.any?
  
        return user
      end
  
      # User doesn't exist - create account based on company_id and create new user
      account = find_or_create_account_by_company(company_id, company_name)
  
      # Generate a random password for the new user
      password = SecureRandom.hex(16)
  
      # Create the new user
      user = account.users.build(
        email: email,
        first_name: first_name || '',
        last_name: last_name || '',
        password: password,
        role: User::ADMIN_ROLE
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
        # Try to find by ID first (handle both string and integer)
        company_id_int = company_id.to_i
        account = Account.active.find_by(id: company_id_int) if company_id_int > 0
        
        # If not found by ID, try to find by UUID
        account ||= Account.active.find_by(uuid: company_id.to_s) if account.nil?
        
        if account
          Rails.logger.info("Found existing account: #{account.id} (#{account.name}) for company_id: #{company_id}")
          return account
        else
          Rails.logger.info("Account not found for company_id: #{company_id}, creating new account")
          # Account not found - create new one with company_id reference
          account_name = company_name.present? ? company_name : "Company #{company_id}"
          account = Account.create!(
            name: account_name,
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
          Rails.logger.info("Found existing account: #{account.id} (#{account.name}) for company_name: #{company_name}")
          return account
        else
          Rails.logger.info("Account not found for company_name: #{company_name}, creating new account")
          # Account not found - create new one
          account = Account.create!(
            name: company_name,
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
        app_url = Docuseal.default_url_options[:host] || request.host
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
  end
  
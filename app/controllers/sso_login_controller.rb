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
        company_id = decoded_token['company_id'] || decoded_token['account_id'] || decoded_token['organization_id']
        company_name = decoded_token['company_name'] || decoded_token['account_name'] || decoded_token['organization_name']
  
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
      # Find or create account based on company_id
      account = find_or_create_account_by_company(company_id, company_name)
  
      # Try to find existing user by email (email is unique globally)
      user = User.find_by(email: email)
  
      if user
        # User exists - check if they're in the correct account
        if user.account_id != account.id
          # User exists but in a different account
          # Move user to the correct account if company_id is provided
          if company_id.present?
            Rails.logger.info("Moving user #{email} from account #{user.account_id} to account #{account.id} (company_id: #{company_id})")
            user.update(account_id: account.id)
          else
            # If no company_id provided, keep user in existing account but log warning
            Rails.logger.warn("User #{email} exists in account #{user.account_id} but company_id not provided in token")
            account = user.account # Use existing account
          end
        end
  
        # Update user info if provided and different
        update_attrs = {}
        update_attrs[:first_name] = first_name if first_name.present? && user.first_name != first_name
        update_attrs[:last_name] = last_name if last_name.present? && user.last_name != last_name
        
        user.update(update_attrs) if update_attrs.any?
  
        return user
      end
  
      # User doesn't exist, create a new one in the specified account
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
      # If company_id is provided, try to find account by ID or UUID
      if company_id.present?
        # Try to find by ID first
        account = Account.active.find_by(id: company_id)
        
        # If not found by ID, try to find by UUID
        account ||= Account.active.find_by(uuid: company_id.to_s) if account.nil?
        
        return account if account
      end
  
      # If company_name is provided, try to find by name
      if company_name.present?
        account = Account.active.find_by(name: company_name)
        return account if account
      end
  
      # If no company_id or company_name provided, or account not found
      # Check if this is the first user (no accounts exist)
      if Account.active.count.zero?
        # Create the first default account
        account = create_default_account(company_name || 'Default Account')
        return account
      end
  
      # If company_id/name not provided and accounts exist, we need to create a new account
      # Use company_name if provided, otherwise generate a unique name
      account_name = if company_name.present?
                       company_name
                     elsif company_id.present?
                       "Company #{company_id}"
                     else
                       "Company #{SecureRandom.hex(4)}"
                     end
  
      # Create new account for this company
      account = Account.create!(
        name: account_name,
        timezone: 'UTC',
        locale: 'en-US'
      )
  
      # Initialize account with required configs
      initialize_account_configs(account)
  
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
  
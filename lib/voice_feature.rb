# frozen_string_literal: true

module VoiceFeature
  # Add SSO user emails allowed to use voice fields and summarization.
  ALLOWED_USER_EMAILS = %w[
    admin@admin.com
  ].freeze

  # Add account IDs (from accounts table) allowed for all users in that account.
  ALLOWED_ACCOUNT_IDS = [].freeze

  # Add facility/company IDs from SSO JWT (facility_id / tpms_admin_id on accounts).
  ALLOWED_TPMS_ADMIN_IDS = [].freeze

  module_function

  def enabled_for?(account:, user: nil)
    return false if account.blank?

    normalized_email = user&.email.to_s.downcase.strip

    if normalized_email.present? && ALLOWED_USER_EMAILS.include?(normalized_email)
      return true
    end

    if ALLOWED_ACCOUNT_IDS.include?(account.id)
      return true
    end

    tpms_admin_id = account.tpms_admin_id.to_s.presence

    if tpms_admin_id.present? && ALLOWED_TPMS_ADMIN_IDS.include?(tpms_admin_id)
      return true
    end

    false
  end

  def enabled_for_submitter?(submitter)
    account = submitter.submission.account

    return true if enabled_for?(account: account)

    account.users.active.exists?(email: ALLOWED_USER_EMAILS)
  end
end

# frozen_string_literal: true

module RestrictedInvitationEmailAccounts
  RESTRICTED_ACCOUNT_IDS = [229].freeze

  RESTRICTED_TPMS_ADMIN_IDS = %w[1181].freeze

  module_function

  def restricted_for?(account)
    return false if account.blank?

    return true if RESTRICTED_ACCOUNT_IDS.include?(account.id)

    tpms_admin_id = account.tpms_admin_id.to_s.presence

    tpms_admin_id.present? && RESTRICTED_TPMS_ADMIN_IDS.include?(tpms_admin_id)
  end
end

# frozen_string_literal: true

class AddTpmsAdminIdToAccounts < ActiveRecord::Migration[8.0]
  def change
    add_column :accounts, :tpms_admin_id, :string
  end
end
